from typing import Any, List, Optional, Union
from enum import Enum

from pydantic import BaseModel, Field, field_serializer, SerializationInfo

from preprocess_utils.models.action import Actions
from preprocess_utils.models.alert import SecurityAlert, SupervisionAlert


class TicketAction(BaseModel):
    sistemaorigen: str
    operacion: Actions
    securityalerts: Union[List[SecurityAlert], SecurityAlert] = Field(
        default_factory=list
    )
    supervisionalerts: Union[List[SupervisionAlert], SupervisionAlert] = Field(
        default_factory=list
    )
    ticketattachments: List[str] = Field(default_factory=list)
    activities: List[str] = Field(default_factory=list)
    tickets: List[str] = Field(default_factory=list)
    vulnerabilities: List[str] = Field(default_factory=list)
    portalraw: Optional[str] = Field(default=None)
    rawEvent: Optional[Union[SecurityAlert, SupervisionAlert]] = Field(default=None)

    def model_post_init(self, *args, **kwargs):
        if isinstance(self.securityalerts, SecurityAlert):
            self.securityalerts = [self.securityalerts]
        # elif isinstance(data.get("supervisionalerts", None), SupervisionAlert):...
        if self.rawEvent is None:
            if self.securityalerts:
                self.rawEvent = self.securityalerts[0]
            elif self.supervisionalerts:
                self.rawEvent = self.supervisionalerts[0]

    @field_serializer("operacion")
    def serialize_dt(self, field: Any, _info: SerializationInfo):
        if _info.field_name in ("operacion") and isinstance(field, Enum):
            return field.value
        return field
