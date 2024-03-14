from typing import Any, List, MutableMapping, Optional
from datetime import datetime

from pydantic import BaseModel, Field, field_serializer, SerializationInfo


class Event(BaseModel):
    eventId: Optional[str] = Field(default=None)
    sourceChildrenEvents: List[str] = Field(default_factory=list)
    sourceEventId: Optional[str] = Field(default=None)
    sourceEventLevel: Optional[str] = Field(default=None)
    sourceParentEvent: Optional[str] = Field(default=None)
    timestamp: Optional[datetime] = Field(default=None)

    @field_serializer("timestamp")
    def serialize_dt(self, field: Any, _info: SerializationInfo):
        if _info.field_name in ("timestamp") and isinstance(field, datetime):
            return field.timestamp() * 1000
        return field


# event notification
class NotificationEvent(BaseModel):
    areasOfConcern: List[str] = Field(default_factory=list)
    extensions: MutableMapping[str, Any] = Field(default_factory=dict)
    impact: Optional[str] = Field(default=None)
    name: Optional[str] = Field(default=None)
    tags: MutableMapping[str, Any] = Field(default_factory=dict)
    tlp: Optional[str] = Field(default=None)


# securityevent
class SecurityEvent(Event, NotificationEvent):
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
    user: Optional[str] = Field(default=None)
    vendor: Optional[str] = Field(default=None)
