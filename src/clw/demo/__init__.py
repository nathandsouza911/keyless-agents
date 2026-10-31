"""Demo mode: the quick start's fictional tenant on fake Graph (v0.1; SD-051).

Demo mode exists so someone can see Cloud Locksmith working in minutes with
no Microsoft tenant, no Azure account and no credentials. It must be
impossible to use it with anything real:

- the api refuses to start in demo mode when ENVIRONMENT=production or when
  any real Entra sign-in setting is configured (check_api);
- the demo broker refuses to start when ENVIRONMENT=production or when any
  real profile credential (CLW_PROFILE_*) is in its environment
  (check_broker), and it uses a built-in fictional identity provider whose
  tokens are unsigned, so Microsoft would refuse them anyway;
- the demo broker serves the reserved fictional tenant only, and every
  normal broker refuses that tenant (MsalCertificateProvider's demo guard);
- the demo broker trusts only the quick start's own CA for Graph's host
  name, which inside the quick start's network is the fake Graph;
- every page shows a DEMO MODE banner.
"""

from __future__ import annotations

from collections.abc import Mapping

# The reserved fictional tenant and its one person (a security lead). Never a real tenant: the
# normal broker refuses this tenant id outright (SD-051).
DEMO_TENANT_ID = "d3e0d3e0-0000-4000-8000-000000000001"
DEMO_TENANT_NAME = "Contoso (fictional demo tenant)"
DEMO_USER_OID = "d3e0d3e0-0000-4000-8000-0000000000aa"
DEMO_USER_ROLE = "security_lead"
REAL_SIGN_IN_SETTINGS = ("MICROSOFT_CLIENT_ID", "MICROSOFT_CLIENT_SECRET", "OIDC_REDIRECT_URI")


class DemoModeRefused(RuntimeError):
    """Demo mode was asked for somewhere it must never run."""


def check_api(settings) -> None:
    """Refuse to start the api in demo mode with anything real configured."""
    if not settings.CLW_DEMO_MODE:
        return
    if settings.is_production:
        raise DemoModeRefused("demo mode is refused when ENVIRONMENT=production")
    configured = [name for name in REAL_SIGN_IN_SETTINGS if getattr(settings, name) not in (None, "")]
    if configured:
        raise DemoModeRefused(f"demo mode is refused while real Entra sign-in settings are set: {configured}")


def check_broker(environ: Mapping[str, str]) -> None:
    """Refuse to start the demo broker with anything real configured."""
    if environ.get("ENVIRONMENT") == "production":
        raise DemoModeRefused("the demo broker is refused when ENVIRONMENT=production")
    real = sorted(name for name, value in environ.items() if name.startswith("CLW_PROFILE_") and value)
    if real:
        raise DemoModeRefused(f"the demo broker is refused while real profile credentials are set: {real}")
