from datetime import datetime
from enum import Enum
from typing import Any, List, MutableMapping, Optional

from pydantic import BaseModel, Field, SerializationInfo, field_serializer

from preprocess_utils.models.event import SecurityEvent
from preprocess_utils.models.severity import Severity


class Alert(BaseModel):
    alertId: str
    clientId: int
    tenantId: str
    socId: str
    service: str
    sourceId: str
    sourceType: str
    severity: Severity
    areasOfConcern: List[str] = Field(default_factory=list)
    impact: str = Field(default=None)
    assets: List[str] = Field(default_factory=list)
    case: MutableMapping[str, Any] = Field(default_factory=dict)
    categorizedAt: Optional[datetime] = Field(default=None)
    detectedAt: Optional[datetime] = Field(default=None)
    operationalCategory: Optional[str] = Field(default=None)
    signature: Optional[str] = Field(default=None)
    sourceAlertId: str = Field(default=None)
    ticket: Optional[str] = Field(default=None)
    updatedAt: Optional[datetime] = Field(default=None)
    via: Optional[str] = Field(default=None)
    serviceId: Optional[str] = Field(default=None)
    extensions: MutableMapping[str, str] = Field(default_factory=dict)
    name: Optional[str] = Field(default=None)
    tags: MutableMapping[str, Any] = Field(default_factory=dict)
    tlp: Optional[str] = Field(default=None)

    def model_post_init(self, *args, **kwargs):
        if self.via is None:
            self.via = "XSOAR"
        if self.serviceId is None:
            self.serviceId = "9"


class SecurityAlert(Alert):
    events: List[SecurityEvent] = Field(default_factory=list)
    directive: Optional[str] = Field(default=None)
    risk: Optional[Severity] = Field(default=None)
    attackLocation: Optional[str] = Field(default=None)
    destinationAddress: Optional[str] = Field(default=None)
    destinationHostname: Optional[str] = Field(default=None)
    destinationPort: Optional[str] = Field(default=None)
    destinationRange: Optional[str] = Field(default=None)
    deviceAddress: Optional[str] = Field(default=None)
    deviceHostname: Optional[str] = Field(default=None)
    enisaCategory: Optional[str] = Field(default=None)
    product: Optional[str] = Field(default=None)
    sensor: Optional[str] = Field(default=None)
    sourceAddress: Optional[str] = Field(default=None)
    sourceHostname: Optional[str] = Field(default=None)
    sourcePort: Optional[str] = Field(default=None)
    sourceRange: Optional[str] = Field(default=None)
    users: List[str] = Field(default_factory=list)
    vendor: Optional[str] = Field(default=None)

    @field_serializer("severity", "risk", "detectedAt", "categorizedAt", "updatedAt")
    def serialize_dt(self, field: Any, _info: SerializationInfo):
        if _info.field_name == "severity" and isinstance(field, Enum):
            return field.name
        elif _info.field_name == "risk" and isinstance(field, Enum):
            return field.value
        elif _info.field_name == "risk" and field is None:
            return self.severity.value
        elif _info.field_name in (
            "detectedAt",
            "categorizedAt",
            "updatedAt",
        ) and isinstance(field, datetime):
            return field.timestamp() * 1000
        return field


class SupervisionAlert(Alert):
    pass
