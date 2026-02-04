"""
NetBox VitalQIP Plugin

Display VitalQIP IPAM data on Device and VirtualMachine detail pages.
Shows IP address assignments from VitalQIP and allows importing addresses from QIP to NetBox.
"""

import logging

from netbox.plugins import PluginConfig

__version__ = "0.1.3"

logger = logging.getLogger(__name__)


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

    def ready(self):
        """Register endpoint view if netbox_endpoints is available."""
        super().ready()
        self._register_endpoint_views()

    def _register_endpoint_views(self):
        """Register VitalQIP tab for Endpoints if plugin is installed."""
        try:
            from django.shortcuts import render
            from netbox.views import generic
            from netbox_endpoints.models import Endpoint

            # Check if already registered
            from utilities.views import ViewTab, register_model_view, registry

            from .views import should_show_vitalqip_tab_endpoint

            views_dict = registry.get("views", {})
            endpoint_views = views_dict.get("netbox_endpoints", {}).get("endpoint", [])
            if any(v.get("name") == "vitalqip" for v in endpoint_views):
                return  # Already registered

            @register_model_view(Endpoint, name="vitalqip", path="vitalqip")
            class EndpointVitalQIPView(generic.ObjectView):
                """Display VitalQIP IPAM data for an Endpoint."""

                queryset = Endpoint.objects.all()
                template_name = "netbox_vitalqip/endpoint_tab.html"

                tab = ViewTab(
                    label="VitalQIP",
                    weight=9200,
                    permission="netbox_endpoints.view_endpoint",
                    hide_if_empty=False,
                    visible=should_show_vitalqip_tab_endpoint,
                )

                def get(self, request, pk):
                    endpoint = Endpoint.objects.get(pk=pk)
                    return render(
                        request,
                        self.template_name,
                        {
                            "object": endpoint,
                            "tab": self.tab,
                            "loading": True,
                        },
                    )

            logger.info("Registered VitalQIP tab for Endpoint model")
        except ImportError:
            logger.debug("netbox_endpoints not installed, skipping endpoint view registration")
        except Exception as e:
            logger.warning(f"Could not register endpoint views: {e}")


config = VitalQIPConfig
