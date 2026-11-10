"""Provider registry: the one place that knows which providers exist.

To add a provider: implement ``Provider`` (see base.py), then add it to ``_factories``.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING

from webscan.providers.base import Provider

if TYPE_CHECKING:
    from webscan.context import RunContext


def _factories() -> dict[str, Callable[[RunContext], Provider]]:
    from webscan.providers.hackertarget.provider import HackerTargetProvider
    from webscan.providers.local.provider import LocalChecksProvider
    from webscan.providers.quantro.provider import QuantroProvider
    from webscan.providers.stubs import STUB_PROVIDERS

    factories: dict[str, Callable[[RunContext], Provider]] = {
        HackerTargetProvider.name: HackerTargetProvider,
        LocalChecksProvider.name: LocalChecksProvider,
        QuantroProvider.name: QuantroProvider,
    }
    factories.update({cls.name: cls for cls in STUB_PROVIDERS})
    return factories


def all_provider_names() -> list[str]:
    return list(_factories())


def target_providers(ctx: RunContext, include_wip: bool = False) -> list[Provider]:
    """Providers that run per target during a scan (Quantro is file-based and ingested separately)."""
    from webscan.providers.stubs import STUB_PROVIDERS

    stub_names = {cls.name for cls in STUB_PROVIDERS}
    providers: list[Provider] = []
    for name, factory in _factories().items():
        if name == "quantro":
            continue
        provider = factory(ctx)
        if name in stub_names:
            # WIP stubs run only when explicitly asked for (mock data) or approved for live use.
            if include_wip or name in ctx.providers_cfg.get("approved_providers", []):
                providers.append(provider)
        elif provider.is_enabled():
            providers.append(provider)
    return providers
