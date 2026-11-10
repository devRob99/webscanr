"""🚧 WIP third-party providers. All are disabled unless the organization approves them."""

from webscan.providers.stubs.base import StubProvider
from webscan.providers.stubs.geoip import GeoIpProvider
from webscan.providers.stubs.hibp import HibpProvider
from webscan.providers.stubs.local_llm import LocalLlmProvider
from webscan.providers.stubs.lookalike import LookalikeProvider
from webscan.providers.stubs.nvd import NvdProvider
from webscan.providers.stubs.rdap import RdapProvider
from webscan.providers.stubs.reputation import ReputationProvider
from webscan.providers.stubs.shodan import ShodanProvider

STUB_PROVIDERS: list[type[StubProvider]] = [
    NvdProvider,
    RdapProvider,
    GeoIpProvider,
    HibpProvider,
    ShodanProvider,
    ReputationProvider,
    LookalikeProvider,
    LocalLlmProvider,
]
