"""
Views for NetBox VitalQIP plugin.

Provides device/VM tab views, settings page, and prefix import functionality.
"""

import logging

from dcim.models import Device
from django.conf import settings
from django.contrib.auth.mixins import LoginRequiredMixin, PermissionRequiredMixin
from django.http import HttpResponse
from django.shortcuts import redirect, render
from django.template.loader import render_to_string
from django.views import View
from ipam.models import IPAddress, Prefix
from netbox.views import generic
from tenancy.models import Tenant
from utilities.views import ViewTab, register_model_view
from virtualization.models import VirtualMachine

from .forms import QIPSettingsForm
from .qip_client import get_client

logger = logging.getLogger(__name__)

# Check if netbox_endpoints plugin is installed
try:
    from netbox_endpoints.models import Endpoint
    ENDPOINTS_PLUGIN_INSTALLED = True
except ImportError:
    ENDPOINTS_PLUGIN_INSTALLED = False


def get_device_ips(device):
    """
    Get all IP addresses associated with a device.

    Returns list of IP address strings.
    """
    ips = []

    # Primary IPs
    if device.primary_ip4:
        ips.append(str(device.primary_ip4.address.ip))
    if device.primary_ip6:
        ips.append(str(device.primary_ip6.address.ip))

    # All assigned IPs from interfaces
    for interface in device.interfaces.all():
        for ip in interface.ip_addresses.all():
            ip_str = str(ip.address.ip)
            if ip_str not in ips:
                ips.append(ip_str)

    return ips


def get_vm_ips(vm):
    """
    Get all IP addresses associated with a VM.

    Returns list of IP address strings.
    """
    ips = []

    # Primary IPs
    if vm.primary_ip4:
        ips.append(str(vm.primary_ip4.address.ip))
    if vm.primary_ip6:
        ips.append(str(vm.primary_ip6.address.ip))

    # All assigned IPs from interfaces
    for interface in vm.interfaces.all():
        for ip in interface.ip_addresses.all():
            ip_str = str(ip.address.ip)
            if ip_str not in ips:
                ips.append(ip_str)

    return ips


@register_model_view(Device, name="vitalqip", path="vitalqip")
class DeviceVitalQIPView(generic.ObjectView):
    """Display VitalQIP IPAM data for a device with async loading."""

    queryset = Device.objects.all()
    template_name = "netbox_vitalqip/device_tab.html"
    tab = ViewTab(
        label="VitalQIP",
        weight=9200,
        permission="dcim.view_device",
        hide_if_empty=False,
    )

    def get(self, request, pk):
        """Render initial tab with loading spinner - content loads via htmx."""
        device = Device.objects.get(pk=pk)
        return render(
            request,
            self.template_name,
            {
                "object": device,
                "tab": self.tab,
                "loading": True,
            },
        )


class DeviceVitalQIPContentView(LoginRequiredMixin, PermissionRequiredMixin, View):
    """HTMX endpoint that returns VitalQIP content for async loading."""

    permission_required = "dcim.view_device"

    def get(self, request, pk):
        """Fetch VitalQIP data and return HTML content."""
        device = Device.objects.prefetch_related("interfaces__ip_addresses").get(pk=pk)
        context = {"object": device}

        # Get QIP client
        client = get_client()
        if not client:
            context["error"] = "VitalQIP not configured. Configure the plugin in NetBox settings."
            return HttpResponse(
                render_to_string(
                    "netbox_vitalqip/device_tab_content.html",
                    context,
                    request=request,
                )
            )

        # Get device IPs
        device_ips = get_device_ips(device)
        if not device_ips:
            context["no_ips"] = True
            context["message"] = "No IP addresses assigned to this device."
            return HttpResponse(
                render_to_string(
                    "netbox_vitalqip/device_tab_content.html",
                    context,
                    request=request,
                )
            )

        # Search for each IP in VitalQIP (limit to first 5 to avoid slow loads)
        qip_addresses = []
        for ip in device_ips[:5]:
            qip_data = client.search_address(ip)
            if qip_data:
                qip_addresses.append(
                    {
                        "netbox_ip": ip,
                        "qip_data": qip_data,
                        "cached": qip_data.get("cached", False),
                    }
                )

        context.update(
            {
                "device_ips": device_ips,
                "qip_addresses": qip_addresses,
                "found_count": len(qip_addresses),
                "total_count": len(device_ips),
                "truncated": len(device_ips) > 5,
            }
        )

        return HttpResponse(
            render_to_string(
                "netbox_vitalqip/device_tab_content.html",
                context,
                request=request,
            )
        )


@register_model_view(VirtualMachine, name="vitalqip", path="vitalqip")
class VMVitalQIPView(generic.ObjectView):
    """Display VitalQIP IPAM data for a virtual machine with async loading."""

    queryset = VirtualMachine.objects.all()
    template_name = "netbox_vitalqip/vm_tab.html"
    tab = ViewTab(
        label="VitalQIP",
        weight=9200,
        permission="virtualization.view_virtualmachine",
        hide_if_empty=False,
    )

    def get(self, request, pk):
        """Render initial tab with loading spinner - content loads via htmx."""
        vm = VirtualMachine.objects.get(pk=pk)
        return render(
            request,
            self.template_name,
            {
                "object": vm,
                "tab": self.tab,
                "is_vm": True,
                "loading": True,
            },
        )


class VMVitalQIPContentView(LoginRequiredMixin, PermissionRequiredMixin, View):
    """HTMX endpoint that returns VitalQIP content for VMs."""

    permission_required = "virtualization.view_virtualmachine"

    def get(self, request, pk):
        """Fetch VitalQIP data and return HTML content."""
        vm = VirtualMachine.objects.prefetch_related("interfaces__ip_addresses").get(pk=pk)
        context = {"object": vm, "is_vm": True}

        # Get QIP client
        client = get_client()
        if not client:
            context["error"] = "VitalQIP not configured. Configure the plugin in NetBox settings."
            return HttpResponse(
                render_to_string(
                    "netbox_vitalqip/device_tab_content.html",
                    context,
                    request=request,
                )
            )

        # Get VM IPs
        vm_ips = get_vm_ips(vm)
        if not vm_ips:
            context["no_ips"] = True
            context["message"] = "No IP addresses assigned to this VM."
            return HttpResponse(
                render_to_string(
                    "netbox_vitalqip/device_tab_content.html",
                    context,
                    request=request,
                )
            )

        # Search for each IP in VitalQIP (limit to first 5 to avoid slow loads)
        qip_addresses = []
        for ip in vm_ips[:5]:
            qip_data = client.search_address(ip)
            if qip_data:
                qip_addresses.append(
                    {
                        "netbox_ip": ip,
                        "qip_data": qip_data,
                        "cached": qip_data.get("cached", False),
                    }
                )

        context.update(
            {
                "device_ips": vm_ips,
                "qip_addresses": qip_addresses,
                "found_count": len(qip_addresses),
                "total_count": len(vm_ips),
                "truncated": len(vm_ips) > 5,
            }
        )

        return HttpResponse(
            render_to_string(
                "netbox_vitalqip/device_tab_content.html",
                context,
                request=request,
            )
        )


class QIPSettingsView(generic.ObjectView):
    """Display VitalQIP plugin settings."""

    queryset = Device.objects.none()
    template_name = "netbox_vitalqip/settings.html"

    def get(self, request):
        config = settings.PLUGINS_CONFIG.get("netbox_vitalqip", {})
        form = QIPSettingsForm(initial=config)

        # Test connection if configured
        connection_status = None
        client = get_client()
        if client:
            result = client.test_connection()
            if result.get("success"):
                connection_status = {
                    "success": True,
                    "message": result.get("message", "Connected"),
                }
            else:
                connection_status = {
                    "success": False,
                    "message": result.get("error", "Connection failed"),
                }

        context = {
            "form": form,
            "config": config,
            "connection_status": connection_status,
            "configured": bool(config.get("qip_url") and config.get("qip_username") and config.get("qip_password")),
        }

        return render(request, self.template_name, context)


class TestConnectionView(generic.ObjectView):
    """Test VitalQIP connection endpoint."""

    queryset = Device.objects.none()

    def get(self, request):
        from django.http import JsonResponse

        client = get_client()
        if not client:
            return JsonResponse(
                {
                    "success": False,
                    "error": "VitalQIP not configured",
                }
            )

        result = client.test_connection()
        return JsonResponse(result)


class PrefixImportView(generic.ObjectView):
    """Search VitalQIP for networks/prefixes to import."""

    queryset = Device.objects.none()
    template_name = "netbox_vitalqip/prefix_import.html"

    def get(self, request):
        context = {}
        return render(request, self.template_name, context)


def is_valid_ip(ip_str):
    """Check if string is a valid IPv4 address."""
    import re
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if not re.match(pattern, ip_str):
        return False
    parts = ip_str.split('.')
    return all(0 <= int(part) <= 255 for part in parts)


class PrefixImportPreviewView(generic.ObjectView):
    """Preview networks from VitalQIP to import as prefixes, or single IP lookup."""

    queryset = Device.objects.none()
    template_name = "netbox_vitalqip/prefix_import_preview.html"

    def get(self, request):
        pattern = request.GET.get("pattern", "").strip()
        if not pattern:
            return redirect("plugins:netbox_vitalqip:prefix_import")

        client = get_client()
        if not client:
            context = {
                "pattern": pattern,
                "error": "VitalQIP not configured",
            }
            return render(request, self.template_name, context)

        # Check if this is a full IP address (no wildcard)
        if "*" not in pattern and is_valid_ip(pattern):
            return self._handle_single_ip(request, client, pattern)

        # Validate wildcard pattern format
        if "*" not in pattern:
            context = {
                "pattern": pattern,
                "error": "Enter a wildcard pattern (e.g., 10.*) or a full IP address (e.g., 192.168.1.1)",
            }
            return render(request, self.template_name, context)

        # Get networks from QIP matching the pattern
        qip_networks = client.get_networks(pattern)

        if not qip_networks:
            context = {
                "pattern": pattern,
                "error": f"No networks found in VitalQIP matching '{pattern}'",
            }
            return render(request, self.template_name, context)

        # Get existing NetBox prefixes to check which ones already exist
        existing_prefixes = set()
        for prefix in Prefix.objects.all():
            existing_prefixes.add(str(prefix.prefix))

        # Categorize networks
        new_networks = []
        existing_networks = []

        for network in qip_networks:
            address = network.get("address", "")
            mask_length = network.get("maskLength", 24)
            name = network.get("name", "")

            if not address:
                continue

            prefix_str = f"{address}/{mask_length}"
            network["prefix_str"] = prefix_str

            if prefix_str in existing_prefixes:
                existing_networks.append(network)
            else:
                new_networks.append(network)

        # Sort by prefix for easier viewing
        new_networks.sort(key=lambda x: x.get("prefix_str", ""))
        existing_networks.sort(key=lambda x: x.get("prefix_str", ""))

        context = {
            "pattern": pattern,
            "mode": "prefix",
            "qip_networks": qip_networks,
            "new_networks": new_networks,
            "existing_networks": existing_networks,
            "new_count": len(new_networks),
            "existing_count": len(existing_networks),
            "total_count": len(qip_networks),
        }

        return render(request, self.template_name, context)

    def _handle_single_ip(self, request, client, ip_address):
        """Handle lookup and import of a single IP address."""
        # Search for the IP in VitalQIP
        qip_data = client.search_address(ip_address)

        if not qip_data:
            context = {
                "pattern": ip_address,
                "mode": "ip",
                "error": f"IP address {ip_address} not found in VitalQIP",
            }
            return render(request, self.template_name, context)

        # Check if IP already exists in NetBox
        address_str = f"{ip_address}/32"
        existing = IPAddress.objects.filter(address=address_str).first()

        # Build DNS name from QIP data
        dns_name = ""
        obj_name = qip_data.get("objectName", "")
        domain = qip_data.get("domainName", "")
        if obj_name and domain:
            dns_name = f"{obj_name}.{domain}"
        elif obj_name:
            dns_name = obj_name

        context = {
            "pattern": ip_address,
            "mode": "ip",
            "qip_data": qip_data,
            "ip_address": ip_address,
            "dns_name": dns_name,
            "existing_ip": existing,
            "can_import": existing is None,
        }

        return render(request, self.template_name, context)

    def post(self, request):
        """Import selected networks as prefixes or single IP in NetBox."""
        from django.http import JsonResponse

        import_mode = request.POST.get("import_mode", "prefix")

        client = get_client()
        if not client:
            return JsonResponse({"success": False, "error": "VitalQIP not configured"})

        # Get OHSU tenant
        try:
            tenant = Tenant.objects.get(slug="ohsu")
        except Tenant.DoesNotExist:
            tenant = None

        # Handle single IP import
        if import_mode == "ip":
            ip_address = request.POST.get("ip_address")
            dns_name = request.POST.get("dns_name", "")

            if not ip_address:
                return JsonResponse({"success": False, "error": "No IP address provided"})

            address_str = f"{ip_address}/32"

            # Check if already exists
            if IPAddress.objects.filter(address=address_str).exists():
                return JsonResponse({"success": False, "error": f"IP {ip_address} already exists in NetBox"})

            try:
                # Get QIP data for description
                qip_data = client.search_address(ip_address)
                description = ""
                if qip_data:
                    obj_class = qip_data.get("objectClass", "")
                    obj_name = qip_data.get("objectName", "")
                    description = f"Imported from VitalQIP: {obj_class or obj_name}"

                new_ip = IPAddress(
                    address=address_str,
                    status="active",
                    dns_name=dns_name[:200] if dns_name else "",
                    description=description[:200],
                    tenant=tenant,
                )
                new_ip.save()

                return JsonResponse({
                    "success": True,
                    "created": 1,
                    "message": f"Imported IP {ip_address} with DNS name '{dns_name}'",
                })

            except Exception as e:
                logger.error(f"Error importing IP {ip_address} from VitalQIP: {e}")
                return JsonResponse({"success": False, "error": str(e)})

        # Handle prefix import (existing code)
        selected_prefixes = request.POST.getlist("selected_prefixes")

        if not selected_prefixes:
            return JsonResponse({"success": False, "error": "No prefixes selected"})

        created = 0
        errors = []

        for prefix_data in selected_prefixes:
            try:
                # Parse prefix_data (format: "address/mask|name")
                parts = prefix_data.split("|", 1)
                prefix_str = parts[0]
                description = parts[1] if len(parts) > 1 else ""

                # Check if already exists
                if Prefix.objects.filter(prefix=prefix_str).exists():
                    continue

                # Determine status based on mask length
                # /16 and larger = container, smaller = active
                mask_length = int(prefix_str.split("/")[1])
                status = "container" if mask_length <= 16 else "active"

                new_prefix = Prefix(
                    prefix=prefix_str,
                    status=status,
                    description=description[:200] if description else "",
                    tenant=tenant,
                )
                new_prefix.save()
                created += 1

            except Exception as e:
                errors.append(f"{prefix_data}: {str(e)}")
                logger.error(f"Error importing prefix from VitalQIP: {e}")

        result = {
            "success": True,
            "created": created,
            "errors": errors,
            "message": f"Imported {created} prefixes",
        }

        if errors:
            result["message"] += f" ({len(errors)} errors)"

        return JsonResponse(result)


# Endpoint-specific functions for netbox_endpoints plugin
def get_endpoint_ips(endpoint):
    """
    Get all IP addresses associated with an endpoint.

    Returns list of IP address strings.
    """
    ips = []

    # Primary IPs from the endpoint
    if endpoint.primary_ip4:
        ips.append(str(endpoint.primary_ip4.address.ip))
    if endpoint.primary_ip6:
        ips.append(str(endpoint.primary_ip6.address.ip))

    return ips


def should_show_vitalqip_tab_endpoint(endpoint):
    """
    Determine if the VitalQIP tab should be visible for this endpoint.

    Shows tab if endpoint has any IP addresses assigned.
    """
    if not ENDPOINTS_PLUGIN_INSTALLED:
        return False

    return endpoint.primary_ip4 is not None or endpoint.primary_ip6 is not None


# Endpoint views - only available if netbox_endpoints is installed
if ENDPOINTS_PLUGIN_INSTALLED:

    class EndpointVitalQIPContentView(LoginRequiredMixin, PermissionRequiredMixin, View):
        """HTMX endpoint that returns VitalQIP content for Endpoint async loading."""

        permission_required = "netbox_endpoints.view_endpoint"

        def get(self, request, pk):
            """Fetch VitalQIP data and return HTML content."""
            endpoint = Endpoint.objects.get(pk=pk)
            context = {"object": endpoint}

            # Get QIP client
            client = get_client()
            if not client:
                context["error"] = "VitalQIP not configured. Configure the plugin in NetBox settings."
                return HttpResponse(
                    render_to_string(
                        "netbox_vitalqip/device_tab_content.html",
                        context,
                        request=request,
                    )
                )

            # Get endpoint IPs
            endpoint_ips = get_endpoint_ips(endpoint)
            if not endpoint_ips:
                context["no_ips"] = True
                context["message"] = "No IP addresses assigned to this endpoint."
                return HttpResponse(
                    render_to_string(
                        "netbox_vitalqip/device_tab_content.html",
                        context,
                        request=request,
                    )
                )

            # Search for each IP in VitalQIP
            qip_addresses = []
            for ip in endpoint_ips:
                qip_data = client.search_address(ip)
                if qip_data:
                    qip_addresses.append(
                        {
                            "netbox_ip": ip,
                            "qip_data": qip_data,
                            "cached": qip_data.get("cached", False),
                        }
                    )

            context.update(
                {
                    "device_ips": endpoint_ips,
                    "qip_addresses": qip_addresses,
                    "found_count": len(qip_addresses),
                    "total_count": len(endpoint_ips),
                    "truncated": False,
                }
            )

            return HttpResponse(
                render_to_string(
                    "netbox_vitalqip/device_tab_content.html",
                    context,
                    request=request,
                )
            )
