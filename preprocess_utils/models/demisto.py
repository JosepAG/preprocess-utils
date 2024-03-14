from enum import Enum
from typing import Any, List, MutableMapping, Optional, Union

from pydantic import BaseModel, Field, SerializationInfo, field_serializer

from preprocess_utils.models.action import Actions
from preprocess_utils.models.service import Services
from preprocess_utils.models.ticket_action import TicketAction
from preprocess_utils.models.alert import SecurityAlert, SupervisionAlert


class CustomFields(BaseModel):
    clientid: int
    socid: int
    tenantid: int
    ticketsource: str
    service: Services = Services.SECURITY
    operation: Actions = Actions.CREATE
    raw: Optional[Union[SecurityAlert, SupervisionAlert]] = None
    ticketactionqueue: Union[List[TicketAction], TicketAction] = Field(
        default_factory=list
    )
    securityalerts: Union[List[SecurityAlert], SecurityAlert] = Field(
        default_factory=list
    )

    def model_post_init(self, *args, **kwargs):
        if isinstance(self.ticketactionqueue, TicketAction):
            self.ticketactionqueue = [self.ticketactionqueue]
        if isinstance(self.securityalerts, SecurityAlert):
            self.securityalerts = [self.securityalerts]
        # elif isinstance(data.get("supervisionalerts", None), SupervisionAlert):...
        if self.raw is None:
            if self.securityalerts:
                self.raw = self.securityalerts[0]

    @field_serializer("service", "operation", "raw")
    def serialize_dt(self, field: Any, _info: SerializationInfo):
        if _info.field_name in ("service", "operation") and isinstance(field, Enum):
            return field.value
        elif _info.field_name == "raw" and isinstance(field, BaseModel):
            return field.model_dump_json()
        return field

    def to_dict(
        self, *, exclude_defaults=True, exclude_none=True, exclude_unset=True
    ) -> MutableMapping[str, str]:
        return self.model_dump(
            exclude_defaults=exclude_defaults,
            exclude_none=exclude_none,
            exclude_unset=exclude_unset,
        )
