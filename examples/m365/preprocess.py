from datetime import datetime
from json import dump, load
from pprint import pprint

from preprocess_utils.models.event import SecurityEvent
from preprocess_utils.models.alert import SecurityAlert
from preprocess_utils.models.ticket_action import TicketAction
from preprocess_utils.models.service import Services
from preprocess_utils.models.severity import Severity
from preprocess_utils.models.action import Actions
from preprocess_utils.models.demisto import CustomFields
from preprocess_utils.mapper import Mapper
from preprocess_utils.transformers.date import str_date_to_datetime


def transform_str_date_to_datetime(str_date: str) -> datetime:
    return str_date_to_datetime(str_date, "%Y-%m-%dT%H:%M:%S.%fZ")


def transform_string_to_severity(severity: str):
    if severity == "informational":
        return Severity.Low
    return Severity[severity.capitalize()]


def get_security_event(evidence_mapper: Mapper, alertid: int) -> SecurityEvent:
    return SecurityEvent(
        eventId=alertid,
        timestamp=evidence_mapper.get(
            "createdDateTime", transformer=transform_str_date_to_datetime
        ),
        enisaCategory="Other",
        product="Microsoft",
        tags={"technology": "Microsoft"},
        extensions={
            "@odata.type": evidence_mapper.get("@odata.type", delimiter="*"),
            "createdDateTime": evidence_mapper.get("createdDateTime"),
            "verdict": evidence_mapper.get("verdict"),
            "remediationStatus": evidence_mapper.get("remediationStatus"),
            "remediationStatusDetails": evidence_mapper.get("remediationStatusDetails"),
            "roles": ", ".join(evidence_mapper.get("roles", default=[])),
            "detailedRoles": ", ".join(
                evidence_mapper.get("detailedRoles", default=[])
            ),
            "tags": ", ".join(evidence_mapper.get("tags", default=[])),
        },
    )


def get_custom_fields(
    clientid: int,
    tenantid: int,
    socid: int,
    securityalert: SecurityAlert,
    ticketaction: TicketAction,
):
    return CustomFields(
        clientid=clientid,
        ticketsource="M365_Alert",
        socid=socid,
        tenantid=tenantid,
        service=Services.SECURITY,
        operation=Actions.CREATE,
        ticketactionqueue=ticketaction,
        securityalerts=securityalert,
    )


def get_ticketaction(securityalert: SecurityAlert):
    return TicketAction(
        sistemaorigen="Microsoft Graph Security",
        operacion=Actions.CREATE,
        securityalerts=securityalert,
    )


def get_securityalert(
    clientid: int, tenantid: int, socid: int, alertraw_mapper: Mapper
):
    events = [
        get_security_event(Mapper(evidence), alertraw_mapper.get("id"))
        for evidence in alertraw_mapper.get("evidence", default=[])
    ]

    return SecurityAlert(
        clientId=clientid,
        socId=socid,
        tenantId=tenantid,
        sourceId=alertraw_mapper.get("detectorId"),
        severity=alertraw_mapper.get(
            "severity", transformer=transform_string_to_severity
        ),
        alertId=alertraw_mapper.get("id"),
        sourceAlertId=alertraw_mapper.get("id"),
        sourceType="M365_PRUEBAS",
        categorizedAt=alertraw_mapper.get(
            "createdDateTime", default=None, transformer=transform_str_date_to_datetime
        ),
        detectedAt=alertraw_mapper.get(
            "createdDateTime", default=None, transformer=transform_str_date_to_datetime
        ),
        updatedAt=alertraw_mapper.get(
            "lastUpdateDateTime",
            default=None,
            transformer=transform_str_date_to_datetime,
        ),
        events=events,
        name=alertraw_mapper.get("title"),
        extensions={
            "tenantId": alertraw_mapper.get("tenantId", default="N/P"),
            "alertWebUrl": alertraw_mapper.get("alertWebUrl", default="N/P"),
            "incidentWebUrl": alertraw_mapper.get("incidentWebUrl", default=""),
            "category": alertraw_mapper.get("category", default="N/P"),
            "tenantId": alertraw_mapper.get("tenantId", default="N/P"),
            "description": alertraw_mapper.get("description", default=""),
        },
    )


def main():
    socid = "1"
    tenantid = "1"
    clientid = 43194
    with open("./examples/m365/M365_alert.json") as f:
        incident = load(f)
    alertraw_mapper = Mapper(incident)
    securityalert = get_securityalert(
        clientid=clientid,
        socid=socid,
        tenantid=tenantid,
        alertraw_mapper=alertraw_mapper,
    )
    ticketaction = get_ticketaction(securityalert=securityalert)
    custom_fields = get_custom_fields(
        clientid=clientid,
        socid=socid,
        tenantid=tenantid,
        securityalert=securityalert,
        ticketaction=ticketaction,
    )
    _custom_fields_dict = custom_fields.model_dump(
        exclude_defaults=True, exclude_none=True, exclude_unset=True
    )
    assert isinstance(_custom_fields_dict, dict)
    pprint(_custom_fields_dict)
    with open("./output_m365.json", "w") as f:
        dump(_custom_fields_dict, f)


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
