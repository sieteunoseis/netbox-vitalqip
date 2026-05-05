from django.db import models


class Vitalqip(models.Model):
    """Unmanaged model to register custom permissions for the VitalQIP plugin."""

    # Excluded from NetBox's /core/system/ object-count loop; the model has no DB table.
    _netbox_private = True

    class Meta:
        managed = False
        default_permissions = ()
        permissions = (
            ("configure_vitalqip", "Can configure VitalQIP plugin settings"),
        )
