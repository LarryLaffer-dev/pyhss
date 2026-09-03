# HSS-initiated network teardown and profile push helpers.
# Copyright 2026 volte.io
# SPDX-License-Identifier: AGPL-3.0-or-later
"""
Shared helpers for HSS-initiated Diameter procedures (CLR, Cx RTR, SWx RTR, Cx PPR).

Used by the REST API and OAM endpoints to tear down live EPC/IMS/VoWiFi sessions
when a subscriber is deleted, blocked, or administratively deregistered.
"""

from __future__ import annotations

import traceback
from typing import List, Optional, Sequence

from database import IMS_SUBSCRIBER


def get_ims_domain(mcc: str, mnc: str) -> str:
    """Return the IMS home domain (Private User Identity realm)."""
    return f"ims.mnc{str(mnc).zfill(3)}.mcc{str(mcc).zfill(3)}.3gppnetwork.org"


def normalize_peer_hostname(peer_field: Optional[str]) -> Optional[str]:
    """Strip Diameter peer metadata suffix (peer;originHost) and return hostname."""
    if not peer_field:
        return None
    return str(peer_field).split(";")[0]


def normalize_scscf_destination(scscf: Optional[str]) -> Optional[str]:
    """Normalize stored S-CSCF name to a Diameter Destination-Host."""
    if not scscf:
        return None
    host = str(scscf).replace("sip:", "")
    if ";" in host:
        host = host.split(";")[0]
    return host


def build_public_identities(ims_subscriber: dict, domain: str) -> List[str]:
    """Build the set of IMPUs for Cx RTR from stored IMS subscriber data."""
    identities: List[str] = []
    msisdn = ims_subscriber.get("msisdn")
    if msisdn:
        identities.append(f"sip:+{msisdn}@{domain}")
        identities.append(f"tel:+{msisdn}")
    msisdn_list = ims_subscriber.get("msisdn_list") or ""
    for entry in str(msisdn_list).split(","):
        entry = entry.strip()
        if not entry:
            continue
        identities.append(f"sip:+{entry}@{domain}")
        identities.append(f"tel:+{entry}")
    imsi = ims_subscriber.get("imsi")
    if imsi:
        identities.append(f"sip:{imsi}@{domain}")
    # Preserve order, drop duplicates.
    return list(dict.fromkeys(identities))


def _log(log_tool, redis_messaging, level: str, message: str) -> None:
    if log_tool is not None:
        log_tool.log(service="API", level=level, message=message, redisClient=redis_messaging)


def _send_clr(
    diameter_client,
    subscriber_info: dict,
    imsi: str,
    warnings: List[str],
    log_tool=None,
    redis_messaging=None,
) -> None:
    serving_mme = subscriber_info.get("serving_mme")
    serving_mme_realm = subscriber_info.get("serving_mme_realm")
    serving_mme_peer = normalize_peer_hostname(subscriber_info.get("serving_mme_peer"))

    if serving_mme_peer and serving_mme_realm and serving_mme:
        try:
            diameter_client.sendDiameterRequest(
                requestType="CLR",
                hostname=serving_mme_peer,
                imsi=imsi,
                DestinationHost=serving_mme,
                DestinationRealm=serving_mme_realm,
                CancellationType=2,
                immediateReattach=False,
            )
            _log(log_tool, redis_messaging, "info", f"[network_control] Sent targeted CLR for IMSI {imsi} to {serving_mme_peer}")
        except Exception as exc:
            msg = f"CLR to serving MME failed for IMSI {imsi}: {exc}"
            warnings.append(msg)
            _log(log_tool, redis_messaging, "error", f"[network_control] {msg}\n{traceback.format_exc()}")

    try:
        diameter_client.broadcastDiameterRequest(
            requestType="CLR",
            peerType="MME",
            imsi=imsi,
            DestinationHost=serving_mme,
            DestinationRealm=serving_mme_realm,
            CancellationType=2,
            immediateReattach=False,
        )
    except Exception as exc:
        msg = f"CLR broadcast to MME peers failed for IMSI {imsi}: {exc}"
        warnings.append(msg)
        _log(log_tool, redis_messaging, "error", f"[network_control] {msg}\n{traceback.format_exc()}")


def _send_cx_rtr(
    diameter_client,
    ims_subscriber_info: dict,
    imsi: str,
    ims_domain: str,
    warnings: List[str],
    log_tool=None,
    redis_messaging=None,
) -> None:
    serving_scscf = ims_subscriber_info.get("scscf")
    serving_scscf_realm = ims_subscriber_info.get("scscf_realm")
    serving_scscf_peer = normalize_peer_hostname(ims_subscriber_info.get("scscf_peer"))
    destination_host = normalize_scscf_destination(serving_scscf)
    public_identities = build_public_identities(ims_subscriber_info, ims_domain)

    if serving_scscf_peer and serving_scscf_realm and destination_host:
        try:
            diameter_client.sendDiameterRequest(
                requestType="RTR",
                hostname=serving_scscf_peer,
                imsi=imsi,
                domain=ims_domain,
                destinationHost=destination_host,
                destinationRealm=serving_scscf_realm,
                publicIdentities=public_identities,
            )
            _log(log_tool, redis_messaging, "info", f"[network_control] Sent targeted Cx RTR for IMSI {imsi} to {serving_scscf_peer}")
        except Exception as exc:
            msg = f"Cx RTR to serving S-CSCF failed for IMSI {imsi}: {exc}"
            warnings.append(msg)
            _log(log_tool, redis_messaging, "error", f"[network_control] {msg}\n{traceback.format_exc()}")

    try:
        diameter_client.broadcastDiameterRequest(
            requestType="RTR",
            peerType="SCSCF",
            imsi=imsi,
            domain=ims_domain,
            destinationHost=destination_host,
            destinationRealm=serving_scscf_realm,
            publicIdentities=public_identities,
        )
    except Exception as exc:
        msg = f"Cx RTR broadcast to S-CSCF peers failed for IMSI {imsi}: {exc}"
        warnings.append(msg)
        _log(log_tool, redis_messaging, "error", f"[network_control] {msg}\n{traceback.format_exc()}")


def _send_swx_rtr(
    diameter_client,
    imsi: str,
    diameter_realm: str,
    warnings: List[str],
    log_tool=None,
    redis_messaging=None,
) -> None:
    try:
        diameter_client.broadcastDiameterRequest(
            requestType="SWX_RTR",
            peerType="aaa",
            imsi=imsi,
            destinationRealm=diameter_realm,
        )
        _log(log_tool, redis_messaging, "info", f"[network_control] Broadcast SWx RTR for IMSI {imsi}")
    except Exception as exc:
        msg = f"SWx RTR broadcast failed for IMSI {imsi}: {exc}"
        warnings.append(msg)
        _log(log_tool, redis_messaging, "error", f"[network_control] {msg}\n{traceback.format_exc()}")


def teardown_subscriber(
    diameter_client,
    database_client,
    imsi: str,
    domains: Optional[Sequence[str]] = None,
    diameter_realm: Optional[str] = None,
    mcc: Optional[str] = None,
    mnc: Optional[str] = None,
    clear_serving_state: bool = True,
    log_tool=None,
    redis_messaging=None,
) -> List[str]:
    """
    Send HSS-initiated teardown messages for the given IMSI.

    domains: subset of 'epc', 'ims', 'swx' (default: all three).
    Returns a list of non-fatal warning strings.
    """
    warnings: List[str] = []
    active_domains = set(domains or ("epc", "ims", "swx"))

    subscriber_info: dict = {}
    ims_subscriber_info: dict = {}

    try:
        subscriber_info = database_client.Get_Subscriber(imsi=str(imsi))
    except Exception:
        subscriber_info = {}

    try:
        ims_subscriber_info = database_client.Get_IMS_Subscriber(imsi=str(imsi))
    except Exception:
        ims_subscriber_info = {}

    resolved_mcc = mcc or getattr(diameter_client, "MCC", "999")
    resolved_mnc = mnc or getattr(diameter_client, "MNC", "999")
    ims_domain = get_ims_domain(resolved_mcc, resolved_mnc)
    resolved_realm = diameter_realm or subscriber_info.get("serving_mme_realm") or ims_subscriber_info.get("scscf_realm")

    if "epc" in active_domains:
        _send_clr(diameter_client, subscriber_info, imsi, warnings, log_tool, redis_messaging)
        if clear_serving_state:
            try:
                database_client.Update_Serving_MME(imsi=imsi, serving_mme=None)
            except Exception as exc:
                warnings.append(f"Failed to clear serving MME for IMSI {imsi}: {exc}")

    if "ims" in active_domains:
        _send_cx_rtr(
            diameter_client,
            ims_subscriber_info,
            imsi,
            ims_domain,
            warnings,
            log_tool,
            redis_messaging,
        )
        if clear_serving_state:
            try:
                database_client.Update_Serving_CSCF(imsi=imsi, serving_cscf=None)
            except Exception as exc:
                warnings.append(f"Failed to clear serving S-CSCF for IMSI {imsi}: {exc}")

    if "swx" in active_domains and resolved_realm:
        _send_swx_rtr(diameter_client, imsi, resolved_realm, warnings, log_tool, redis_messaging)

    return warnings


def push_ims_profile(
    diameter_client,
    ims_subscriber: dict,
    mcc: Optional[str] = None,
    mnc: Optional[str] = None,
    log_tool=None,
    redis_messaging=None,
) -> List[str]:
    """
    Send Cx PPR to the serving S-CSCF when the subscriber is IMS-registered.

    Returns a list of non-fatal warning strings.
    """
    warnings: List[str] = []
    imsi = ims_subscriber.get("imsi")
    serving_scscf = ims_subscriber.get("scscf")
    serving_scscf_realm = ims_subscriber.get("scscf_realm")
    serving_scscf_peer = normalize_peer_hostname(ims_subscriber.get("scscf_peer"))
    destination_host = normalize_scscf_destination(serving_scscf)

    if not imsi or not serving_scscf_peer or not serving_scscf_realm or not destination_host:
        _log(
            log_tool,
            redis_messaging,
            "debug",
            f"[network_control] Skipping Cx PPR for IMSI {imsi}: no serving S-CSCF on record",
        )
        return warnings

    resolved_mcc = mcc or getattr(diameter_client, "MCC", "999")
    resolved_mnc = mnc or getattr(diameter_client, "MNC", "999")
    ims_domain = get_ims_domain(resolved_mcc, resolved_mnc)

    try:
        cx_user_data = diameter_client.build_cx_user_data(ims_subscriber)
    except Exception as exc:
        msg = f"Failed to build Cx-User-Data for PPR (IMSI {imsi}): {exc}"
        warnings.append(msg)
        _log(log_tool, redis_messaging, "error", f"[network_control] {msg}\n{traceback.format_exc()}")
        return warnings

    try:
        diameter_client.sendDiameterRequest(
            requestType="PPR",
            hostname=serving_scscf_peer,
            imsi=imsi,
            domain=ims_domain,
            destinationHost=destination_host,
            destinationRealm=serving_scscf_realm,
            cxUserData=cx_user_data,
        )
        _log(log_tool, redis_messaging, "info", f"[network_control] Sent Cx PPR for IMSI {imsi} to {serving_scscf_peer}")
    except Exception as exc:
        msg = f"Cx PPR to serving S-CSCF failed for IMSI {imsi}: {exc}"
        warnings.append(msg)
        _log(log_tool, redis_messaging, "error", f"[network_control] {msg}\n{traceback.format_exc()}")

    return warnings


def ims_profile_push_fields_changed(old_subscriber: dict, patch_body: dict) -> bool:
    """Return True when a PATCH touches fields that require a Cx PPR."""
    watched = ("ifc_template_id", "ifc_path", "msisdn", "msisdn_list")
    return any(field in patch_body for field in watched)


def push_ppr_for_ifc_template_subscribers(
    diameter_client,
    database_client,
    ifc_template_id: int,
    mcc: Optional[str] = None,
    mnc: Optional[str] = None,
    log_tool=None,
    redis_messaging=None,
) -> List[str]:
    """Fan out Cx PPR to registered IMS subscribers using the given iFC template."""
    warnings: List[str] = []
    try:
        for entry in database_client.GetAll(IMS_SUBSCRIBER):
            if str(entry.get("ifc_template_id")) != str(ifc_template_id):
                continue
            if not entry.get("scscf") or not entry.get("scscf_peer"):
                continue
            warnings.extend(
                push_ims_profile(
                    diameter_client,
                    entry,
                    mcc=mcc,
                    mnc=mnc,
                    log_tool=log_tool,
                    redis_messaging=redis_messaging,
                )
            )
    except Exception as exc:
        warnings.append(f"PPR fan-out for iFC template {ifc_template_id} failed: {exc}")
        _log(log_tool, redis_messaging, "error", f"[network_control] {traceback.format_exc()}")
    return warnings
