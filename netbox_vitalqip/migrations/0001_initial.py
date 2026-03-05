from django.db import migrations


class Migration(migrations.Migration):

    initial = True

    dependencies = []

    operations = [
        migrations.CreateModel(
            name="Vitalqip",
            fields=[],
            options={
                "managed": False,
                "default_permissions": (),
                "permissions": (
                    ("configure_vitalqip", "Can configure VitalQIP plugin settings"),
                ),
            },
        ),
    ]
