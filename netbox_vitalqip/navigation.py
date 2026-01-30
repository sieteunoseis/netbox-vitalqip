"""
Navigation menu for NetBox VitalQIP plugin.
"""

from netbox.plugins import PluginMenu, PluginMenuItem

menu = PluginMenu(
    label="VitalQIP",
    groups=(
        (
            "IPAM",
            (
                PluginMenuItem(
                    link="plugins:netbox_vitalqip:prefix_import",
                    link_text="Import from QIP",
                    permissions=["ipam.add_ipaddress"],
                ),
            ),
        ),
        (
            "Settings",
            (
                PluginMenuItem(
                    link="plugins:netbox_vitalqip:settings",
                    link_text="Configuration",
                    permissions=["dcim.view_device"],
                ),
            ),
        ),
    ),
    icon_class="mdi mdi-ip-network",
)
