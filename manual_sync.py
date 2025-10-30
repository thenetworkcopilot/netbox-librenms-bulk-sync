# manual_sync.py
"""
NetBox LibreNMS Plugin Bulk Sync Script

This script automates the synchronization of network device data from LibreNMS
to NetBox using the netbox-librenms-plugin. It processes multiple sites and
devices automatically, syncing interfaces, cables, IP addresses, and setting
primary IPs.

Author: Rishi
Repository: [Your GitHub URL]
License: MIT

Requirements:
    - NetBox with netbox-librenms-plugin installed
    - NetBox API token with appropriate permissions
    - Python 3.8+ with dependencies from requirements.txt
"""

import os
import requests
import logging
import time
from urllib.parse import urljoin
from bs4 import BeautifulSoup

# --- Basic Logging Setup ---
logging.basicConfig(
    level=logging.INFO, 
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("LibreNMS_Bulk_Sync")

# --- Environment Variables ---
NETBOX_URL = os.getenv("NETBOX_URL")
NETBOX_TOKEN = os.getenv("NETBOX_TOKEN")
NETBOX_USERNAME = os.getenv("NETBOX_USERNAME")
NETBOX_PASSWORD = os.getenv("NETBOX_PASSWORD")

if not all([NETBOX_URL, NETBOX_TOKEN, NETBOX_USERNAME, NETBOX_PASSWORD]):
    raise ValueError(
        "Missing required environment variables! "
        "Required: NETBOX_URL, NETBOX_TOKEN, NETBOX_USERNAME, NETBOX_PASSWORD"
    )

# --- NetBox REST API Functions ---

def get_netbox_api_session():
    """
    Returns a requests session configured for NetBox REST API.
    Uses token-based authentication.
    """
    session = requests.Session()
    session.headers.update({
        'Authorization': f'Token {NETBOX_TOKEN}',
        'Content-Type': 'application/json',
        'Accept': 'application/json',
    })
    return session


def get_devices_by_site_and_role(site_slug, role_name="switch"):
    """
    Fetches devices from NetBox using the REST API.
    
    Args:
        site_slug: The site slug (e.g., 'winchester', 'new_york')
        role_name: Device role name (default: 'switch')
    
    Returns:
        List of device dictionaries or empty list on error
    """
    api_session = get_netbox_api_session()
    try:
        logger.info(f"Fetching devices for site '{site_slug}' with role '{role_name}'...")
        response = api_session.get(
            f"{NETBOX_URL.rstrip('/')}/api/dcim/devices/",
            params={"site": site_slug, "role": role_name},
            timeout=30
        )
        response.raise_for_status()
        data = response.json()
        devices = data.get("results", [])
        logger.info(f"Found {len(devices)} devices via API.")
        return devices
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to fetch devices from NetBox API: {e}")
        return []


def get_device_ip_addresses(device_name):
    """
    Get IP addresses for a device using NetBox REST API.
    
    Args:
        device_name: The device name to query
    
    Returns:
        Dictionary with 'results' key containing list of IP addresses
    """
    api_session = get_netbox_api_session()
    try:
        response = api_session.get(
            f"{NETBOX_URL.rstrip('/')}/api/ipam/ip-addresses/",
            params={"device": device_name},
            timeout=30
        )
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to fetch IP addresses from NetBox API: {e}")
        return {"results": []}


def update_device_primary_ip(device_id, ip_id):
    """
    Update device primary IPv4 address using NetBox REST API.
    
    Args:
        device_id: NetBox device ID
        ip_id: NetBox IP address ID to set as primary
    
    Returns:
        True if successful, False otherwise
    """
    api_session = get_netbox_api_session()
    try:
        response = api_session.patch(
            f"{NETBOX_URL.rstrip('/')}/api/dcim/devices/{device_id}/",
            json={"primary_ip4": ip_id},
            timeout=30
        )
        response.raise_for_status()
        return True
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to update device primary IP via NetBox API: {e}")
        return False


# --- NetBox Web Session Functions (for Plugin Interaction) ---

def get_netbox_session(username, password):
    """
    Logs into NetBox web interface to get an authenticated session.
    This is required for interacting with the LibreNMS plugin UI.
    
    Args:
        username: NetBox username
        password: NetBox password
    
    Returns:
        Authenticated requests.Session object or None on failure
    """
    session = requests.Session()
    login_url = urljoin(NETBOX_URL, "/login/")
    
    try:
        logger.info("Attempting to retrieve CSRF token from NetBox login page...")
        r_get = session.get(login_url, timeout=10)
        r_get.raise_for_status()
        
        soup = BeautifulSoup(r_get.text, 'html.parser')
        csrf_token = soup.find('input', {'name': 'csrfmiddlewaretoken'}).get('value')
        logger.info("Successfully retrieved CSRF token.")
    except Exception as e:
        logger.error(f"Failed to get CSRF token from NetBox: {e}")
        return None

    try:
        login_data = {
            "csrfmiddlewaretoken": csrf_token,
            "username": username,
            "password": password,
        }
        logger.info(f"Attempting to log in to NetBox as user '{username}'...")
        r_post = session.post(login_url, data=login_data, headers={"Referer": login_url}, timeout=10)
        r_post.raise_for_status()

        if "Please enter a correct username and password" in r_post.text:
            logger.error("NetBox login failed: Invalid credentials.")
            return None
        
        logger.info("Successfully logged into NetBox and established a session.")
        return session
    except Exception as e:
        logger.error(f"Exception during NetBox login request: {e}")
        return None


# --- LibreNMS Plugin Sync Functions ---

def discover_and_sync_all_interfaces_paginated(session, device_id, base_url):
    """
    Discovers and syncs all interfaces from LibreNMS to NetBox.
    Handles pagination automatically (up to 50 interfaces per page).
    
    Args:
        session: Authenticated requests.Session object
        device_id: NetBox device ID
        base_url: NetBox base URL
    """
    csrf_token = session.cookies.get('csrftoken')
    referer_url = f"{base_url.rstrip('/')}/dcim/devices/{device_id}/librenms-sync/"
    headers = {
        'Referer': referer_url,
        'HX-Request': 'true',
        'HX-Current-URL': referer_url
    }
    
    # Step 1: Trigger the "Refresh Interfaces" action
    try:
        logger.info("Triggering 'Refresh Interfaces' to populate data from LibreNMS...")
        refresh_url = urljoin(base_url, f"/plugins/librenms_plugin/devices/{device_id}/interface-sync/")
        refresh_payload = {'csrfmiddlewaretoken': csrf_token}
        
        res_refresh = session.post(refresh_url, headers=headers, data=refresh_payload, timeout=120)
        res_refresh.raise_for_status()
        logger.info("✓ Successfully triggered interface data refresh.")
        time.sleep(3)
    except Exception as e:
        logger.error(f"Failed to trigger interface refresh for device {device_id}: {e}")
        return

    # Step 2: Process paginated results
    all_interfaces_found = set()
    total_interfaces_synced = 0
    max_pages = 20
    page = 1
    
    logger.info("Starting paginated interface discovery and sync...")
    
    while page <= max_pages:
        logger.info(f"--- Fetching Page {page} ---")
        
        paginated_url = (
            f"/dcim/devices/{device_id}/librenms-sync/"
            f"?tab=interfaces&interfaces_page={page}&interfaces_per_page=50"
        )
        request_url = urljoin(base_url, paginated_url)
        
        try:
            res_page_content = session.get(request_url, headers={'Referer': referer_url}, timeout=60)
            res_page_content.raise_for_status()
            
            soup = BeautifulSoup(res_page_content.text, 'html.parser')
            sync_form = soup.select_one('form[action*="sync-interfaces"]')
            
            if not sync_form:
                logger.warning(f"No sync form found on page {page}. Ending pagination.")
                break
                
            checkboxes = sync_form.find_all('input', {'type': 'checkbox', 'name': 'select'})
            interfaces_on_this_page = [cb.get('value') for cb in checkboxes if cb.get('value')]
            
            if not interfaces_on_this_page:
                logger.info(f"No interfaces found on page {page}. End of data.")
                break

            logger.info(f"Found {len(interfaces_on_this_page)} interfaces on page {page}")
            new_interfaces_to_sync = [iface for iface in interfaces_on_this_page if iface not in all_interfaces_found]

            if not new_interfaces_to_sync and page > 1:
                logger.warning(f"Page {page} contains only previously seen interfaces. Stopping.")
                break
            
            all_interfaces_found.update(new_interfaces_to_sync)
            
            sync_payload = {
                'csrfmiddlewaretoken': csrf_token,
                'select': new_interfaces_to_sync
            }
            sync_url = urljoin(base_url, f"/plugins/librenms_plugin/device/{device_id}/sync-interfaces/?interface_name_field=ifName")
            
            logger.info(f"Syncing {len(new_interfaces_to_sync)} interfaces from page {page}...")
            res_sync = session.post(sync_url, headers={'Referer': request_url}, data=sync_payload, timeout=120)
            res_sync.raise_for_status()
            
            total_interfaces_synced += len(new_interfaces_to_sync)
            logger.info(f"✓ Successfully synced {len(new_interfaces_to_sync)} interfaces.")

            page += 1
            time.sleep(2)
            
        except Exception as e:
            logger.error(f"Error while processing page {page}: {e}")
            break
    
    logger.info(f"Paginated sync complete: Synced {total_interfaces_synced} interfaces across {page-1} pages.")
    logger.info(f"Total unique interfaces discovered: {len(all_interfaces_found)}")


def discover_and_sync_all_cables(session, device_id, base_url):
    """
    Triggers a refresh and syncs all cables for a given device.
    
    Args:
        session: Authenticated requests.Session object
        device_id: NetBox device ID
        base_url: NetBox base URL
    """
    logger.info("Starting cable discovery and sync process...")
    csrf_token = session.cookies.get('csrftoken')
    referer_url = f"{base_url.rstrip('/')}/dcim/devices/{device_id}/librenms-sync/"
    headers = {'Referer': referer_url, 'HX-Request': 'true'}

    # Step 1: Trigger the "Refresh Cables" action
    try:
        logger.info("Triggering 'Refresh Cables' from LibreNMS...")
        refresh_url = urljoin(base_url, f"/plugins/librenms_plugin/devices/{device_id}/cable-sync/")
        refresh_payload = {'csrfmiddlewaretoken': csrf_token}
        res_refresh = session.post(refresh_url, headers=headers, data=refresh_payload, timeout=120)
        res_refresh.raise_for_status()
        logger.info("✓ Successfully triggered cable data refresh.")
        time.sleep(2)
    except Exception as e:
        logger.error(f"Failed to trigger cable refresh for device {device_id}: {e}")
        return

    # Step 2: Fetch and sync cables
    try:
        logger.info("Fetching refreshed cable data...")
        page_url = f"{referer_url}?tab=cables"
        res_page_content = session.get(page_url, headers={'Referer': referer_url}, timeout=60)
        res_page_content.raise_for_status()

        soup = BeautifulSoup(res_page_content.text, 'html.parser')
        sync_form = soup.select_one('form[action*="sync-cables"]')

        if not sync_form:
            logger.info("No cable sync form found. Device may have no cables to sync.")
            return

        checkboxes = sync_form.find_all('input', {'type': 'checkbox', 'name': 'select'})
        cables_to_sync = [cb.get('value') for cb in checkboxes if cb.get('value')]

        if not cables_to_sync:
            logger.info("No new cables found to sync.")
            return
        
        logger.info(f"Found {len(cables_to_sync)} cables to sync.")
        sync_payload = {
            'csrfmiddlewaretoken': csrf_token,
            'select': cables_to_sync
        }
        sync_url = urljoin(base_url, f"/plugins/librenms_plugin/device/{device_id}/sync-cables/")
        
        res_sync = session.post(sync_url, headers={'Referer': page_url}, data=sync_payload, timeout=120)
        res_sync.raise_for_status()
        logger.info(f"✓ Successfully synced {len(cables_to_sync)} cables.")

    except Exception as e:
        logger.error(f"An error occurred during cable sync: {e}")


def discover_and_sync_all_ip_addresses(session, device_id, base_url):
    """
    Triggers a refresh and syncs all IP Addresses for a given device.
    
    Args:
        session: Authenticated requests.Session object
        device_id: NetBox device ID
        base_url: NetBox base URL
    """
    logger.info("Starting IP Address discovery and sync process...")
    csrf_token = session.cookies.get('csrftoken')
    referer_url = f"{base_url.rstrip('/')}/dcim/devices/{device_id}/librenms-sync/"
    headers = {'Referer': referer_url, 'HX-Request': 'true'}

    # Step 1: Trigger the "Refresh IP Addresses" action
    try:
        logger.info("Triggering 'Refresh IP Addresses' from LibreNMS...")
        refresh_url = urljoin(base_url, f"/plugins/librenms_plugin/devices/{device_id}/ipaddress-sync/")
        refresh_payload = {'csrfmiddlewaretoken': csrf_token}
        res_refresh = session.post(refresh_url, headers=headers, data=refresh_payload, timeout=120)
        res_refresh.raise_for_status()
        logger.info("✓ Successfully triggered IP Address data refresh.")
        time.sleep(2)
    except Exception as e:
        logger.error(f"Failed to trigger IP Address refresh for device {device_id}: {e}")
        return

    # Step 2: Fetch and sync IP addresses
    try:
        logger.info("Fetching refreshed IP Address data...")
        page_url = f"{referer_url}?tab=ipaddresses"
        res_page_content = session.get(page_url, headers={'Referer': referer_url}, timeout=60)
        res_page_content.raise_for_status()

        soup = BeautifulSoup(res_page_content.text, 'html.parser')
        sync_form = soup.select_one('form[action*="sync-ip-addresses"]')

        if not sync_form:
            logger.info("No IP Address sync form found. Device may have no IPs to sync.")
            return

        checkboxes = sync_form.find_all('input', {'type': 'checkbox', 'name': 'select'})
        ips_to_sync = [cb.get('value') for cb in checkboxes if cb.get('value')]

        if not ips_to_sync:
            logger.info("No new IP Addresses found to sync.")
            return
            
        logger.info(f"Found {len(ips_to_sync)} IP Addresses to sync.")
        sync_payload = {
            'csrfmiddlewaretoken': csrf_token,
            'select': ips_to_sync
        }
        sync_url = urljoin(base_url, f"/plugins/librenms_plugin/device/{device_id}/sync-ip-addresses/")
        
        res_sync = session.post(sync_url, headers={'Referer': page_url}, data=sync_payload, timeout=120)
        res_sync.raise_for_status()
        logger.info(f"✓ Successfully synced {len(ips_to_sync)} IP Addresses.")

    except Exception as e:
        logger.error(f"An error occurred during IP Address sync: {e}")


def set_primary_ip_for_device(session, device_id, device_name, base_url):
    """
    Finds a suitable IP on a device and sets it as the primary IPv4 address.
    Prefers management interfaces (Vlan1, mgmt0, etc.) but falls back to first available IP.
    
    Args:
        session: Authenticated requests.Session object (unused but kept for consistency)
        device_id: NetBox device ID
        device_name: NetBox device name
        base_url: NetBox base URL (unused but kept for consistency)
    """
    logger.info("Attempting to set a primary IP for the device...")

    # Preferred management interface names (in order of preference)
    management_interface_candidates = [
        'Vlan1', 'vlan1', 'mgmt0', 'Management0', 'lo0', 'Loopback0'
    ]

    try:
        logger.info(f"Querying for IPs using device name: '{device_name}'")
        device_ips = get_device_ip_addresses(device_name)

        if not device_ips or not device_ips.get("results"):
            logger.warning("No IP addresses found for this device. Cannot set a primary IP.")
            return

        primary_ip_id = None
        target_ip_address = ""

        # Try to find an IP on a management interface
        for ip in device_ips["results"]:
            if (ip.get("assigned_object") and 
                ip["assigned_object"].get("name") in management_interface_candidates):
                primary_ip_id = ip.get("id")
                target_ip_address = ip.get("address")
                logger.info(
                    f"Found candidate IP {target_ip_address} on interface "
                    f"'{ip['assigned_object']['name']}'."
                )
                break

        # Fallback to first available IP if no management interface found
        if not primary_ip_id:
            first_ip = device_ips["results"][0]
            primary_ip_id = first_ip.get("id")
            target_ip_address = first_ip.get("address")
            logger.info(
                f"No specific management IP found. Using first available IP: {target_ip_address}."
            )

        logger.info(
            f"Setting {target_ip_address} (ID: {primary_ip_id}) as the primary IP "
            f"for device {device_id}..."
        )

        if update_device_primary_ip(device_id, primary_ip_id):
            logger.info("✓ Successfully set the primary IP.")
        else:
            logger.error("Failed to set primary IP.")

    except Exception as e:
        logger.error(f"An error occurred while setting the primary IP: {e}")


# --- Main Execution ---

def main():
    """
    Main function that orchestrates the bulk sync process.
    
    Process:
        1. Authenticate to NetBox web interface (for plugin interaction)
        2. Loop through configured sites
        3. For each site, get all switch devices
        4. For each device:
           - Sync interfaces (with pagination)
           - Sync cables
           - Sync IP addresses
           - Set primary IP
    """
    logger.info("=" * 70)
    logger.info("Starting NetBox LibreNMS Plugin Bulk Sync")
    logger.info("=" * 70)
    
    # Authenticate to NetBox web interface
    session = get_netbox_session(NETBOX_USERNAME, NETBOX_PASSWORD)
    if not session:
        logger.critical("Could not authenticate to NetBox. Aborting sync.")
        return

    # Configure sites to process
    # These should match the site slugs in NetBox (lowercase, hyphenated)
    target_sites = [
        "winchester",
        "new_york"
    ]
    
    # Process each site
    for site in target_sites:
        logger.info("")
        logger.info("=" * 70)
        logger.info(f"Processing Site: {site.title()}")
        logger.info("=" * 70)
        
        # Get all switch devices for this site using REST API
        devices_to_sync = get_devices_by_site_and_role(site, role_name="switch")
    
        if not devices_to_sync:
            logger.warning(f"No switch devices found for site '{site}'. Skipping.")
            continue
            
        logger.info(f"Found {len(devices_to_sync)} switch(es) to process in {site.title()}.")

        # Process each device
        for i, device in enumerate(devices_to_sync, start=1):
            device_name = device.get("name")
            device_id = device.get("id")
            
            if not all([device_name, device_id]):
                logger.warning(f"Skipping device with missing name or ID: {device}")
                continue
            
            logger.info("")
            logger.info("-" * 70)
            logger.info(f"Processing device {i}/{len(devices_to_sync)}: {device_name} (ID: {device_id})")
            logger.info("-" * 70)

            try:
                # Step 1: Sync Interfaces
                logger.info("--- Step 1: Syncing INTERFACES ---")
                discover_and_sync_all_interfaces_paginated(session, device_id, NETBOX_URL)
                
                # Step 2: Sync Cables
                logger.info("--- Step 2: Syncing CABLES ---")
                discover_and_sync_all_cables(session, device_id, NETBOX_URL)
                
                # Step 3: Sync IP Addresses
                logger.info("--- Step 3: Syncing IP ADDRESSES ---")
                discover_and_sync_all_ip_addresses(session, device_id, NETBOX_URL)
                
                # Step 4: Set Primary IP
                logger.info("--- Step 4: Setting PRIMARY IP ---")
                set_primary_ip_for_device(session, device_id, device_name, NETBOX_URL)

                logger.info(f"✓ Completed all sync processes for {device_name}")

            except Exception as e:
                logger.error(f"An error occurred while syncing {device_name}: {e}")
                logger.info(f"Continuing to next device...")
            
            # Brief pause between devices to avoid overwhelming NetBox
            time.sleep(1)

    logger.info("")
    logger.info("=" * 70)
    logger.info("Bulk sync process complete!")
    logger.info("=" * 70)


if __name__ == "__main__":
    main()
