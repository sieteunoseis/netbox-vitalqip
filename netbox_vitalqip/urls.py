"""
URL routing for NetBox VitalQIP plugin.
"""

from django.urls import path

from .views import (
    DeviceVitalQIPContentView,
    ENDPOINTS_PLUGIN_INSTALLED,
    PrefixImportPreviewView,
    PrefixImportView,
    QIPSettingsView,
    TestConnectionView,
    VMVitalQIPContentView,
)

urlpatterns = [
    path("settings/", QIPSettingsView.as_view(), name="settings"),
    path("test-connection/", TestConnectionView.as_view(), name="test_connection"),
    path("import/", PrefixImportView.as_view(), name="prefix_import"),
    path("import/preview/", PrefixImportPreviewView.as_view(), name="prefix_import_preview"),
    path("device/<int:pk>/content/", DeviceVitalQIPContentView.as_view(), name="device_content"),
    path("vm/<int:pk>/content/", VMVitalQIPContentView.as_view(), name="vm_content"),
]

# Add endpoint URLs if netbox_endpoints is installed
if ENDPOINTS_PLUGIN_INSTALLED:
    from .views import EndpointVitalQIPContentView

    urlpatterns.append(
        path("endpoint/<int:pk>/content/", EndpointVitalQIPContentView.as_view(), name="endpoint_content"),
    )
