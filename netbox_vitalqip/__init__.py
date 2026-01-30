"""
NetBox VitalQIP Plugin

Display VitalQIP IPAM data on Device and VirtualMachine detail pages.
Shows IP address assignments from VitalQIP and allows importing addresses from QIP to NetBox.
"""

from netbox.plugins import PluginConfig

__version__ = "0.1.0"


class VitalQIPConfig(PluginConfig):
    """Plugin configuration for NetBox VitalQIP integration."""

    name = "netbox_vitalqip"
    verbose_name = "VitalQIP IPAM"
    description = "Display VitalQIP IPAM data and import IP addresses"
    version = __version__
    author = "sieteunoseis"
    author_email = "jeremy.worden@gmail.com"
    base_url = "vitalqip"
    min_version = "4.0.0"

    # Required settings - plugin won't load without these
    required_settings = []

    # Default configuration values
    default_settings = {
        "qip_url": "",  # VitalQIP server URL (e.g., https://dhcp.example.com/api)
        "qip_username": "",  # QIP username
        "qip_password": "",  # QIP password
        "qip_organization": "OHSU",  # QIP organization
        "timeout": 30,  # API timeout in seconds
        "cache_timeout": 300,  # Cache data for 5 minutes (QIP is slower)
        "verify_ssl": False,  # SSL verification (False for legacy VitalQIP)
    }


config = VitalQIPConfig
