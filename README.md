# NetBox LibreNMS Plugin Bulk Sync Script

Automates the bulk synchronization of network device data from LibreNMS to NetBox using the [netbox-librenms-plugin](https://github.com/bonzo81/netbox-librenms-plugin). This script processes multiple sites and devices automatically, syncing interfaces, cables, IP addresses, and intelligently setting primary IPs.

## 🎯 What This Does

Instead of manually clicking through the LibreNMS plugin UI for each device:
1. Click "Refresh Interfaces" → Select all → Click "Sync"
2. Click "Refresh Cables" → Select all → Click "Sync"
3. Click "Refresh IP Addresses" → Select all → Click "Sync"
4. Manually select and set primary IP

This script does all of that **automatically** for every device at specified sites.

**Time savings:** ~5-7 minutes per device → ~3 minutes for an entire site

## 📋 Prerequisites

### Required Software
- **NetBox** (tested on v3.6+) with the [netbox-librenms-plugin](https://github.com/bonzo81/netbox-librenms-plugin) installed
- **LibreNMS** configured and monitoring your devices
- **Python 3.8+**

### Required Permissions
The NetBox user account (for both web login and API token) needs:
- `dcim.view_device` - View devices
- `dcim.change_device` - Update device primary IP
- `ipam.view_ipaddress` - View IP addresses
- Access to the LibreNMS plugin interface

### NetBox API Token
Generate an API token in NetBox:
1. Log into NetBox
2. Click your username (top right) → "API Tokens"
3. Click "Add Token"
4. Give it a name (e.g., "Bulk Sync Script")
5. Select the required permissions above
6. Copy the token immediately (you won't see it again!)

## 🚀 Installation
```bash
# Clone the repository
git clone https://github.com/yourusername/netbox-librenms-bulk-sync.git
cd netbox-librenms-bulk-sync

# Install dependencies
pip install -r requirements.txt

# Copy and configure environment variables
cp .env.example .env
# Edit .env with your NetBox credentials
```

## ⚙️ Configuration

### 1. Configure Environment Variables

Edit `.env` with your NetBox details:
```bash
NETBOX_URL=http://your-netbox-instance:8080
NETBOX_TOKEN=your_api_token_from_netbox
NETBOX_USERNAME=your_username
NETBOX_PASSWORD=your_password
```

### 2. Configure Sites to Sync

Edit the `target_sites` list in `manual_sync.py` (around line 471):
```python
target_sites = [
    "your-site-slug",    # Must match NetBox site slug (lowercase, hyphenated)
    "another-site",
]
```

**Note:** Site names should match your NetBox site **slugs** (not display names). Find these in NetBox at: Organization → Sites → [Your Site] → Slug field.

## 📖 Usage

### Basic Usage
```bash
# Load environment variables and run
export $(cat .env | xargs)
python manual_sync.py
```

### Docker Usage (Optional)

If you prefer to run in a container:
```bash
docker run --rm \
  --env-file .env \
  -v $(pwd):/app \
  python:3.11-slim \
  bash -c "cd /app && pip install -r requirements.txt && python manual_sync.py"
```

## 🔧 How It Works

The script uses **two authentication methods** because the LibreNMS plugin has different requirements:

### 1. Session-Based Login (Username/Password)
- Used to interact with the LibreNMS Plugin web UI
- Scrapes HTML forms using BeautifulSoup
- Triggers refresh/sync actions via POST requests
- **Why:** The plugin doesn't expose an API for these actions

### 2. Token-Based API (API Token)
- Used to query devices via NetBox REST API
- Sets primary IP addresses
- **Why:** Standard NetBox API for data operations

## 📊 What Gets Synced

For each device, the script syncs:

### Interfaces
- All physical and virtual interfaces
- Interface names, types, MAC addresses
- Enabled/disabled status
- Handles pagination (50 interfaces per page)

### Cables
- CDP/LLDP discovered connections
- Links to neighboring devices
- Creates cable objects in NetBox

### IP Addresses
- All IPv4/IPv6 addresses discovered on interfaces
- Assigns addresses to correct interfaces

### Primary IP Selection
Intelligently selects the primary IP by preferring (in order):
1. IP on management interfaces: `Vlan1`, `vlan1`, `mgmt0`, `Management0`, `lo0`, `Loopback0`
2. First available IP if no management interface found

## 🐛 Troubleshooting

### "Could not authenticate to NetBox"
- Check your `NETBOX_USERNAME` and `NETBOX_PASSWORD`
- Verify the user has permissions to log into the web interface
- Check `NETBOX_URL` is correct and accessible

### "Failed to fetch devices from NetBox API"
- Check your `NETBOX_TOKEN` is valid
- Verify token has required permissions (`dcim.view_device`, etc.)
- Check `NETBOX_URL` points to your NetBox instance
- Ensure NetBox API is accessible from where you're running the script

### "No devices found for site"
- Verify site slug matches exactly (case-sensitive)
- Check devices have role='switch' in NetBox
- Confirm devices are assigned to the correct site

### "No sync form found"
- Device may not exist in LibreNMS
- Check LibreNMS plugin is installed and configured in NetBox
- Verify device has been discovered in LibreNMS

### "Pagination stops early"
- Normal behavior if device has fewer interfaces than expected
- Check logs for actual interface count discovered

### Import Errors
```bash
# Install missing dependencies
pip install -r requirements.txt

# Or install individually
pip install requests beautifulsoup4 psycopg2-binary
```

## 📝 Example Output
```
======================================================================
Starting NetBox LibreNMS Plugin Bulk Sync
======================================================================

======================================================================
Processing Site: Winchester
======================================================================
Fetching devices for site 'winchester' with role 'switch'...
Found 3 devices via API.
Found 3 switch(es) to process in Winchester.

----------------------------------------------------------------------
Processing device 1/3: sw-winchester-core01 (ID: 42)
----------------------------------------------------------------------
--- Step 1: Syncing INTERFACES ---
Triggering 'Refresh Interfaces' to populate data from LibreNMS...
✓ Successfully triggered interface data refresh.
Starting paginated interface discovery and sync...
--- Fetching Page 1 ---
Found 48 interfaces on page 1
Syncing 48 interfaces from page 1...
✓ Successfully synced 48 interfaces.
--- Fetching Page 2 ---
No interfaces found on page 2. End of data.
Paginated sync complete: Synced 48 interfaces across 1 pages.

--- Step 2: Syncing CABLES ---
Triggering 'Refresh Cables' from LibreNMS...
✓ Successfully triggered cable data refresh.
Found 6 cables to sync.
✓ Successfully synced 6 cables.

--- Step 3: Syncing IP ADDRESSES ---
Triggering 'Refresh IP Addresses' from LibreNMS...
✓ Successfully triggered IP Address data refresh.
Found 12 IP Addresses to sync.
✓ Successfully synced 12 IP Addresses.

--- Step 4: Setting PRIMARY IP ---
Found candidate IP 10.1.100.1/24 on interface 'Vlan1'.
Setting 10.1.100.1/24 (ID: 156) as the primary IP for device 42...
✓ Successfully set the primary IP.
✓ Completed all sync processes for sw-winchester-core01

[... continues for remaining devices ...]

======================================================================
Bulk sync process complete!
======================================================================
```

## 🔒 Security Considerations

### Credentials Storage
- **Never commit `.env` file to version control**
- The `.gitignore` file is configured to exclude `.env`
- Use environment variables or a secrets manager in production

### API Token Permissions
- Use the **minimum required permissions**
- Create a dedicated service account for automation
- Rotate tokens periodically

### Network Access
- Run script from a trusted network or management subnet
- Consider using SSH tunnels if running remotely
- Ensure NetBox uses HTTPS in production

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [NetBox](https://github.com/netbox-community/netbox) - The amazing network IPAM/DCIM tool
- [LibreNMS](https://github.com/librenms/librenms) - Network monitoring system
- [netbox-librenms-plugin](https://github.com/bonzo81/netbox-librenms-plugin) - The plugin that makes this integration possible

## 📧 Support

- **Issues:** Please open an issue on GitHub for bugs or feature requests
- **Discussions:** Use GitHub Discussions for questions and community support

## 🔗 Related Projects

- [Network Copilot AI Agent](https://github.com/yourusername/network-copilot) - AI-powered network management assistant (uses this script for data synchronization)
- [My YouTube Series](https://youtube.com/your-channel) - Video tutorials on network automation with AI

## 📊 Project Status

**Active Development** - This project is actively maintained and used in production environments.

### Roadmap
- [ ] Add support for configurable interface name field selection
- [ ] Implement retry logic for failed API calls
- [ ] Add dry-run mode to preview changes
- [ ] Support for custom field mappings
- [ ] Prometheus metrics export for monitoring sync health
- [ ] Multi-threading support for faster processing

---

**Made with ❤️ by Rishi** | [YouTube](www.youtube.com/@RishiNetworks)
