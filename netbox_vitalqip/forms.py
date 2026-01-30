"""
Forms for NetBox VitalQIP plugin settings.
"""

from django import forms


class QIPSettingsForm(forms.Form):
    """Form for displaying VitalQIP plugin configuration."""

    qip_url = forms.URLField(
        required=False,
        label="VitalQIP API URL",
        help_text="Full URL to VitalQIP API (e.g., https://dhcp.example.com/api)",
        widget=forms.URLInput(attrs={"class": "form-control", "readonly": True}),
    )

    qip_username = forms.CharField(
        required=False,
        label="Username",
        help_text="VitalQIP username",
        widget=forms.TextInput(attrs={"class": "form-control", "readonly": True}),
    )

    qip_password = forms.CharField(
        required=False,
        label="Password",
        help_text="VitalQIP password",
        widget=forms.PasswordInput(attrs={"class": "form-control", "readonly": True}),
    )

    qip_organization = forms.CharField(
        required=False,
        label="Organization",
        help_text="VitalQIP organization name",
        widget=forms.TextInput(attrs={"class": "form-control", "readonly": True}),
    )

    timeout = forms.IntegerField(
        required=False,
        label="Timeout (seconds)",
        help_text="API request timeout in seconds",
        widget=forms.NumberInput(attrs={"class": "form-control", "readonly": True}),
    )

    cache_timeout = forms.IntegerField(
        required=False,
        label="Cache Timeout (seconds)",
        help_text="How long to cache API responses",
        widget=forms.NumberInput(attrs={"class": "form-control", "readonly": True}),
    )

    verify_ssl = forms.BooleanField(
        required=False,
        label="Verify SSL",
        help_text="Verify SSL certificates (usually False for legacy VitalQIP)",
        widget=forms.CheckboxInput(attrs={"class": "form-check-input", "disabled": True}),
    )
