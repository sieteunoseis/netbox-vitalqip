from django.db import models


class Vitalqip(models.Model):
    """Unmanaged model to register custom permissions for the VitalQIP plugin."""

    class Meta:
        managed = False
        default_permissions = ()
        permissions = (
            ("configure_vitalqip", "Can configure VitalQIP plugin settings"),
        )
