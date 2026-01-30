"""
URL routing for NetBox VitalQIP plugin.
"""

from django.urls import path

from .views import (
    PrefixImportPreviewView,
    PrefixImportView,
    QIPSettingsView,
    TestConnectionView,
)

urlpatterns = [
    path("settings/", QIPSettingsView.as_view(), name="settings"),
    path("test-connection/", TestConnectionView.as_view(), name="test_connection"),
    path("import/", PrefixImportView.as_view(), name="prefix_import"),
    path("import/preview/", PrefixImportPreviewView.as_view(), name="prefix_import_preview"),
]
