# NetBox VitalQIP Plugin

[![PyPI](https://img.shields.io/pypi/v/netbox-vitalqip)](https://pypi.org/project/netbox-vitalqip/)
[![Python](https://img.shields.io/pypi/pyversions/netbox-vitalqip)](https://pypi.org/project/netbox-vitalqip/)
[![License](https://img.shields.io/github/license/sieteunoseis/netbox-vitalqip)](https://github.com/sieteunoseis/netbox-vitalqip/blob/main/LICENSE)

A NetBox plugin that integrates with Nokia VitalQIP IPAM to display IP address data and enable importing prefixes and IP addresses from QIP to NetBox.

## Features

- **Device/VM Tabs**: View VitalQIP data for any device or VM based on their assigned IP addresses
- **Prefix Import**: Search VitalQIP for networks using wildcard patterns and import them as prefixes
- **IP Address Import**: Look up individual IP addresses and import them with DNS names
- **Caching**: Results are cached to minimize API calls to VitalQIP

## Requirements

- NetBox 4.0+
- Python 3.10+
- Nokia VitalQIP REST API access

## Installation

```bash
pip install netbox-vitalqip
```

Add to NetBox `configuration.py`:

```python
PLUGINS = [
    'netbox_vitalqip',
]

PLUGINS_CONFIG = {
    'netbox_vitalqip': {
        'qip_url': 'https://dhcp.example.com/api',
        'qip_username': 'your-username',
        'qip_password': 'your-password',
        'qip_organization': 'YourOrg',
        'timeout': 30,
        'cache_timeout': 300,
        'verify_ssl': False,
    },
}
```

## Usage

### Device/VM Tab

Navigate to any Device or VirtualMachine detail page. A "VitalQIP" tab shows:

- IP address assignments in QIP
- Object name and domain
- Subnet information
- Address type (Static/DHCP)

### Import Prefixes

1. Navigate to **VitalQIP > Import from QIP**
2. Enter a wildcard pattern (e.g., `10.*`, `172.16.*`, `192.168.1.*`)
3. Review networks found in VitalQIP:
   - **New**: Networks not yet in NetBox (can be imported)
   - **Existing**: Networks already in NetBox (shown for reference)
4. Select prefixes to import

Imported prefixes include:
- Description from QIP network name
- Appropriate status (Container for /16 and larger, Active for smaller)
- Tenant assignment

### Import Single IP Address

1. Navigate to **VitalQIP > Import from QIP**
2. Enter a full IP address (e.g., `192.168.1.1`)
3. Review the QIP data (object name, domain, class, subnet)
4. Import with DNS name auto-populated from QIP

## API Notes

VitalQIP uses a REST API with legacy TLS requirements. The plugin handles:

- Token-based authentication (login returns Authentication header)
- Legacy SSL/TLS negotiation via OpenSSL configuration
- Response caching to minimize API calls

### Endpoints Used

- `POST /api/login` - Authentication
- `GET /api/v1/{org}/v4address.json` - Search addresses
- `GET /api/v1/{org}/v4network.json` - Get networks
- `GET /api/v1/{org}/v4subnet.json` - Get subnet info

## Development

```bash
cd ~/development/netbox-vitalqip
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## License

Apache 2.0

## Author

[sieteunoseis](https://github.com/sieteunoseis) (jeremy.worden@gmail.com)
