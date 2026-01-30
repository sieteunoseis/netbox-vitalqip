# CLAUDE.md - NetBox VitalQIP Plugin

Development notes for Claude Code when working on this plugin.

## Bootstrap / NetBox UI Notes

### Badge Classes
Use `text-bg-*` instead of `bg-*` for Bootstrap badges in NetBox 4.x (Bootstrap 5.3+):
- `text-bg-success` - automatically uses white text on green background
- `text-bg-info` - automatically uses appropriate contrast text
- `text-bg-warning` - uses dark text on yellow background
- `text-bg-secondary` - uses white text on gray background

The `text-bg-*` classes automatically select appropriate text color for contrast, while `bg-*` requires manually adding `text-white` or `text-dark`.

## VitalQIP API Notes

### Field Names
VitalQIP API returns these field names (not standard REST conventions):
- `objectAddr` - IP address (not `address`)
- `subnetAddr` - Subnet address (not `subnetAddress`)
- `objectName` - Hostname
- `domainName` - DNS domain
- `objectClass` - Device type (Gateway, Server, etc.)
- `dynamicConfig` - "Static" or "DHCP"

### Authentication
- Login endpoint: `POST /api/login` with JSON body `{username, password, organization}`
- Returns `Authentication` header with token
- Use token in subsequent requests: `Authentication: Token {token}`

### Legacy SSL
VitalQIP requires legacy TLS renegotiation. Use OpenSSL config:
```
Options = UnsafeLegacyRenegotiation
```

## Performance Notes

- Limit IP lookups to 5 per device/VM to avoid slow page loads
- Cache timeout is 5 minutes (300 seconds) due to slow QIP API
- Hostname search removed to improve load times
