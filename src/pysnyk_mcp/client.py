"""Lazy-initialised pysnyk client factory.

Reads credentials from environment variables at first use so that
import of this module never fails simply because env vars are unset
(useful for tests, linting and Docker image build).
"""

from __future__ import annotations

import os
from functools import lru_cache
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover
    import snyk


class SnykConfigError(RuntimeError):
    """Raised when Snyk credentials are missing or invalid."""


def _require_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise SnykConfigError(
            f"Environment variable {name} is required. "
            "Set SNYK_TOKEN to your Snyk API token. "
            "Get it from: https://app.snyk.io/account"
        )
    return value


@lru_cache(maxsize=1)
def get_client() -> "snyk.SnykClient":
    """Return a cached SnykClient built from env vars."""
    # Imported lazily so the module can load even if pysnyk is not yet
    # installed (helpful during container builds and unit tests).
    import snyk

    token = _require_env("SNYK_TOKEN")
    url = os.environ.get("SNYK_API_URL", "https://api.snyk.io/v1")

    return snyk.SnykClient(token, url)


def reset_client() -> None:
    """Clear the cached client (primarily for testing)."""
    get_client.cache_clear()
