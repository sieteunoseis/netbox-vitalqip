"""
VitalQIP IPAM API Client

Provides methods to interact with Nokia VitalQIP REST API.
Includes caching to minimize API calls and legacy SSL support.
"""

import json
import logging
import os
import subprocess
import tempfile
from typing import Optional

from django.conf import settings
from django.core.cache import cache

logger = logging.getLogger(__name__)


class QIPClient:
    """Client for Nokia VitalQIP REST API."""

    def __init__(
        self,
        url: str,
        username: str,
        password: str,
        organization: str = "OHSU",
        timeout: int = 30,
        verify_ssl: bool = False,
        cache_timeout: int = 300,
    ):
        """
        Initialize VitalQIP API client.

        Args:
            url: VitalQIP API URL (e.g., https://dhcp.example.com/api)
            username: QIP username
            password: QIP password
            organization: QIP organization name
            timeout: Request timeout in seconds
            verify_ssl: Whether to verify SSL certificates (False for legacy QIP)
            cache_timeout: How long to cache responses in seconds
        """
        self.base_url = url.rstrip("/")
        self.username = username
        self.password = password
        self.organization = organization
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.cache_timeout = cache_timeout
        self._auth_token = None
        self._openssl_conf_path = None

    def _get_openssl_conf_path(self):
        """Create or return path to OpenSSL legacy config for VitalQIP."""
        if self._openssl_conf_path and os.path.exists(self._openssl_conf_path):
            return self._openssl_conf_path

        openssl_conf_content = """openssl_conf = openssl_init

[openssl_init]
ssl_conf = ssl_sect

[ssl_sect]
system_default = system_default_sect

[system_default_sect]
Options = UnsafeLegacyRenegotiation
"""
        conf_path = "/tmp/vitalqip_openssl.cnf"
        if not os.path.exists(conf_path):
            with open(conf_path, "w") as f:
                f.write(openssl_conf_content)
        self._openssl_conf_path = conf_path
        return conf_path

    def _make_curl_request(self, url: str, method: str = "GET", data: dict = None, headers: dict = None) -> dict:
        """
        Make HTTP request using curl with legacy SSL support.

        Args:
            url: Full URL to request
            method: HTTP method (GET, POST)
            data: JSON data for POST requests
            headers: Additional headers

        Returns:
            dict: Response data or {"error": "message"}
        """
        openssl_conf = self._get_openssl_conf_path()

        cmd = ["curl", "-sk", "--max-time", str(self.timeout)]

        if method == "POST":
            cmd.extend(["-X", "POST"])
            if data:
                cmd.extend(["-d", json.dumps(data)])

        # Add headers
        cmd.extend(["-H", "Content-Type: application/json"])
        if headers:
            for key, value in headers.items():
                cmd.extend(["-H", f"{key}: {value}"])

        # Add URL
        cmd.append(url)

        try:
            env = os.environ.copy()
            env["OPENSSL_CONF"] = openssl_conf

            result = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=self.timeout + 30)

            if result.returncode == 0 and result.stdout:
                try:
                    return json.loads(result.stdout)
                except json.JSONDecodeError:
                    logger.error(f"Invalid JSON response: {result.stdout[:200]}")
                    return {"error": "Invalid JSON response from VitalQIP"}
            else:
                error_msg = result.stderr[:200] if result.stderr else "Unknown error"
                logger.error(f"curl failed: {error_msg}")
                return {"error": f"Request failed: {error_msg}"}

        except subprocess.TimeoutExpired:
            logger.error("VitalQIP request timed out")
            return {"error": "Request timed out"}
        except Exception as e:
            logger.error(f"VitalQIP request failed: {e}")
            return {"error": str(e)}

    def _login(self) -> Optional[str]:
        """
        Login to VitalQIP and return auth token.

        Returns:
            str: Authentication token or None on failure
        """
        # Check cache first
        cache_key = f"qip_auth_{self.username}"
        cached_token = cache.get(cache_key)
        if cached_token:
            return cached_token

        login_url = f"{self.base_url}/login"
        login_data = {
            "username": self.username,
            "password": self.password,
            "organization": self.organization,
        }

        openssl_conf = self._get_openssl_conf_path()

        # Use curl to get headers (for auth token)
        cmd = [
            "curl",
            "-sk",
            "--max-time",
            str(self.timeout),
            "-X",
            "POST",
            "-H",
            "Content-Type: application/json",
            "-d",
            json.dumps(login_data),
            "-D",
            "-",  # Output headers
            "-o",
            "/dev/null",  # Discard body
            login_url,
        ]

        try:
            env = os.environ.copy()
            env["OPENSSL_CONF"] = openssl_conf

            result = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=self.timeout + 30)

            if result.returncode == 0:
                # Parse headers for Authentication token
                for line in result.stdout.split("\n"):
                    if line.lower().startswith("authentication:"):
                        token = line.split(":", 1)[1].strip()
                        # Cache token for 10 minutes
                        cache.set(cache_key, token, 600)
                        logger.info(f"Successfully authenticated to VitalQIP as {self.username}")
                        return token

            logger.error("VitalQIP login failed: No token in response")
            return None

        except subprocess.TimeoutExpired:
            logger.error("VitalQIP login timed out")
            return None
        except Exception as e:
            logger.error(f"VitalQIP login error: {e}")
            return None

    def test_connection(self) -> dict:
        """
        Test connection to VitalQIP server.

        Returns:
            dict: {"success": True, "message": "..."} or {"error": "message"}
        """
        token = self._login()
        if not token:
            return {"success": False, "error": "Authentication failed - check credentials"}

        return {
            "success": True,
            "message": f"Connected to VitalQIP as {self.username}@{self.organization}",
        }

    def search_address(self, ip_address: str) -> Optional[dict]:
        """
        Search for an IP address in VitalQIP.

        Args:
            ip_address: IP address to search for (e.g., "10.64.1.100")

        Returns:
            dict: Address info or None if not found
        """
        cache_key = f"qip_addr_{ip_address}"
        cached = cache.get(cache_key)
        if cached is not None:
            cached["cached"] = True
            return cached

        token = self._login()
        if not token:
            return None

        # Search for the address
        url = f"{self.base_url}/v1/{self.organization}/v4address.json?address={ip_address}"

        openssl_conf = self._get_openssl_conf_path()

        cmd = [
            "curl",
            "-sk",
            "--max-time",
            str(self.timeout),
            "-X",
            "GET",
            "-H",
            "Content-Type: application/json",
            "-H",
            f"Authentication: Token {token}",
            url,
        ]

        try:
            env = os.environ.copy()
            env["OPENSSL_CONF"] = openssl_conf

            result = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=self.timeout + 30)

            if result.returncode == 0 and result.stdout:
                try:
                    data = json.loads(result.stdout)
                    if "list" in data and len(data["list"]) > 0:
                        address_info = data["list"][0]
                        address_info["cached"] = False
                        cache.set(cache_key, address_info, self.cache_timeout)
                        return address_info
                    return None
                except json.JSONDecodeError:
                    logger.error(f"Invalid JSON for address search: {result.stdout[:200]}")
                    return None
            return None

        except Exception as e:
            logger.error(f"Error searching address {ip_address}: {e}")
            return None

    def get_subnet(self, subnet_address: str) -> Optional[dict]:
        """
        Get subnet information from VitalQIP.

        Args:
            subnet_address: Subnet address (e.g., "10.64.1.0")

        Returns:
            dict: Subnet info or None if not found
        """
        cache_key = f"qip_subnet_{subnet_address}"
        cached = cache.get(cache_key)
        if cached is not None:
            cached["cached"] = True
            return cached

        token = self._login()
        if not token:
            return None

        url = f"{self.base_url}/v1/{self.organization}/v4subnet.json?address={subnet_address}"

        openssl_conf = self._get_openssl_conf_path()

        cmd = [
            "curl",
            "-sk",
            "--max-time",
            str(self.timeout),
            "-X",
            "GET",
            "-H",
            "Content-Type: application/json",
            "-H",
            f"Authentication: Token {token}",
            url,
        ]

        try:
            env = os.environ.copy()
            env["OPENSSL_CONF"] = openssl_conf

            result = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=self.timeout + 30)

            if result.returncode == 0 and result.stdout:
                try:
                    data = json.loads(result.stdout)
                    if "list" in data and len(data["list"]) > 0:
                        subnet_info = data["list"][0]
                        subnet_info["cached"] = False
                        cache.set(cache_key, subnet_info, self.cache_timeout)
                        return subnet_info
                    return None
                except json.JSONDecodeError:
                    return None
            return None

        except Exception as e:
            logger.error(f"Error getting subnet {subnet_address}: {e}")
            return None

    def get_subnet_addresses(self, subnet_address: str, mask_length: int = 24) -> list:
        """
        Get all addresses in a subnet from VitalQIP.

        Args:
            subnet_address: Subnet address (e.g., "10.64.1.0")
            mask_length: Subnet mask length

        Returns:
            list: List of address dicts
        """
        cache_key = f"qip_subnet_addrs_{subnet_address}_{mask_length}"
        cached = cache.get(cache_key)
        if cached is not None:
            return cached

        token = self._login()
        if not token:
            return []

        # Use wildcard search with pagination (v4addresses endpoint only returns DHCP, not static)
        # Build wildcard pattern from subnet address (e.g., 10.150.20.0 -> 10.150.20.*)
        parts = subnet_address.split(".")
        if mask_length <= 8:
            pattern = f"{parts[0]}.*"
        elif mask_length <= 16:
            pattern = f"{parts[0]}.{parts[1]}.*"
        else:
            pattern = f"{parts[0]}.{parts[1]}.{parts[2]}.*"

        url = f"{self.base_url}/v1/{self.organization}/v4address.json?address={pattern}&pageSize=500"

        openssl_conf = self._get_openssl_conf_path()

        cmd = [
            "curl",
            "-sk",
            "--max-time",
            "90",  # Longer timeout for large subnets
            "-X",
            "GET",
            "-H",
            "Content-Type: application/json",
            "-H",
            f"Authentication: Token {token}",
            url,
        ]

        try:
            env = os.environ.copy()
            env["OPENSSL_CONF"] = openssl_conf

            result = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=120)

            if result.returncode == 0 and result.stdout:
                try:
                    data = json.loads(result.stdout)
                    if "list" in data:
                        addresses = data["list"]
                        cache.set(cache_key, addresses, self.cache_timeout)
                        return addresses
                    return []
                except json.JSONDecodeError:
                    return []
            return []

        except Exception as e:
            logger.error(f"Error getting subnet addresses for {subnet_address}: {e}")
            return []

    def search_by_hostname(self, hostname: str) -> list:
        """
        Search for addresses by hostname in VitalQIP.

        Args:
            hostname: Hostname to search for

        Returns:
            list: List of matching address dicts
        """
        cache_key = f"qip_hostname_{hostname.lower()}"
        cached = cache.get(cache_key)
        if cached is not None:
            return cached

        token = self._login()
        if not token:
            return []

        # Search by object name (hostname)
        url = f"{self.base_url}/v1/{self.organization}/v4address.json?objectName={hostname}"

        openssl_conf = self._get_openssl_conf_path()

        cmd = [
            "curl",
            "-sk",
            "--max-time",
            str(self.timeout),
            "-X",
            "GET",
            "-H",
            "Content-Type: application/json",
            "-H",
            f"Authentication: Token {token}",
            url,
        ]

        try:
            env = os.environ.copy()
            env["OPENSSL_CONF"] = openssl_conf

            result = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=self.timeout + 30)

            if result.returncode == 0 and result.stdout:
                try:
                    data = json.loads(result.stdout)
                    if "list" in data:
                        addresses = data["list"]
                        cache.set(cache_key, addresses, self.cache_timeout)
                        return addresses
                    return []
                except json.JSONDecodeError:
                    return []
            return []

        except Exception as e:
            logger.error(f"Error searching hostname {hostname}: {e}")
            return []

    def get_networks(self, address_pattern: str) -> list:
        """
        Get networks matching an address pattern from VitalQIP.

        Args:
            address_pattern: Address pattern (e.g., "10.64.*")

        Returns:
            list: List of network dicts
        """
        cache_key = f"qip_networks_{address_pattern}"
        cached = cache.get(cache_key)
        if cached is not None:
            return cached

        token = self._login()
        if not token:
            return []

        url = f"{self.base_url}/v1/{self.organization}/v4network.json?address={address_pattern}"

        openssl_conf = self._get_openssl_conf_path()

        cmd = [
            "curl",
            "-sk",
            "--max-time",
            "90",
            "-X",
            "GET",
            "-H",
            "Content-Type: application/json",
            "-H",
            f"Authentication: Token {token}",
            url,
        ]

        try:
            env = os.environ.copy()
            env["OPENSSL_CONF"] = openssl_conf

            result = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=120)

            if result.returncode == 0 and result.stdout:
                try:
                    data = json.loads(result.stdout)
                    if "list" in data:
                        networks = data["list"]
                        cache.set(cache_key, networks, self.cache_timeout)
                        return networks
                    return []
                except json.JSONDecodeError:
                    return []
            return []

        except Exception as e:
            logger.error(f"Error getting networks for {address_pattern}: {e}")
            return []


def get_client() -> Optional[QIPClient]:
    """
    Factory function to get configured VitalQIP client.

    Returns:
        QIPClient instance or None if not configured
    """
    config = settings.PLUGINS_CONFIG.get("netbox_vitalqip", {})

    qip_url = config.get("qip_url")
    username = config.get("qip_username")
    password = config.get("qip_password")

    if not qip_url or not username or not password:
        logger.warning("VitalQIP plugin not configured - missing qip_url, qip_username, or qip_password")
        return None

    return QIPClient(
        url=qip_url,
        username=username,
        password=password,
        organization=config.get("qip_organization", "OHSU"),
        timeout=config.get("timeout", 30),
        verify_ssl=config.get("verify_ssl", False),
        cache_timeout=config.get("cache_timeout", 300),
    )
