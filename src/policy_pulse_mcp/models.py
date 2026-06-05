from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Engine(str, Enum):
    GATEKEEPER = "gatekeeper"
    KYVERNO = "kyverno"
    AZURE_POLICY = "azure_policy"
    STATIC = "static"


@dataclass
class FrameworkRef:
    framework: str
    control_id: str
    control_title: str


@dataclass
class Violation:
    id: str
    engine: Engine
    policy_name: str
    resource_name: str
    resource_kind: str
    namespace: Optional[str]
    message: str
    severity: Severity
    framework_refs: list[FrameworkRef] = field(default_factory=list)
    raw: dict = field(default_factory=dict)


@dataclass
class Policy:
    name: str
    engine: Engine
    kind: str
    enforcement: str
    description: str = ""
    raw: dict = field(default_factory=dict)
