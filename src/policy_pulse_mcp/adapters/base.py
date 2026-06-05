"""EngineAdapter protocol — all adapters must implement this interface."""
from typing import Protocol, runtime_checkable

from ..models import Engine, Policy, Violation


@runtime_checkable
class EngineAdapter(Protocol):
    engine: Engine

    def is_available(self) -> bool:
        """Return True if this engine is reachable."""
        ...

    async def list_policies(self) -> list[Policy]:
        """Return all policies known to this engine."""
        ...

    async def get_violations(self) -> list[Violation]:
        """Return all active violations from this engine."""
        ...
