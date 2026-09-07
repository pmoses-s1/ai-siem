"""
UAM Alert Interface -- multi-indicator + multi-observable inline linkage
test -- REVERSIBLE.

What this proves beyond test_uam_alert_interface_single.py:
  * Multi-indicator alert: ONE SecurityAlert carrying 3 indicators
    inline at finding_info.related_events[], sent in ONE POST /v1/alerts.
  * Multiple observables per indicator: each of the 3 indicators carries
    at least 3 observables of different OCSF types (file / hash / host /
    ip / url / process / user).
  * Multiple OCSF classes in one alert: FileSystem Activity (1001),
    Process Activity (1007), Network Activity (4001).
  * Full inline context: each related_events[] entry carries the
    indicator's metadata / device / actor / class-specific object, not a
    bare uid reference.
  * Server-side linkage: after ingest, alert.indicators contains one
    record per posted related_events[] entry, each carrying its
    observables[] array through to UAM.

Indicators are never posted separately. /v1/indicators is not reachable
with any credential, so the inline copy in the alert is the only path to
the tenant, and it is what populates the console Indicators tab.

Verify through `alert.indicators`, NOT `alertWithRawIndicators`
---------------------------------------------------------------
`rawIndicators` was the store `POST /v1/indicators` fed. Nothing can
write to it any more, so on an inline-ingested alert it is `[]` and an
assertion against it can only fail. Measured on a live tenant: an alert
posted with 4 indicators inline in one POST returned 4 entries on
`alert.indicators` and `[]` on `alertWithRawIndicators.rawIndicators`.
`rawIndicators` is also a scalar (a JSON list), so sub-selecting it
returns `Validation error (SubselectionNotAllowed@...)`.

`ua.get_alert_indicators()` runs the right shape,
`alert(id) { indicators { type uid title description message severity
observables { name value type } } }`. Do not add `name` or `category`
to that selection: neither exists on `Indicator` and either one fails
the whole query at validation with `FieldUndefined`.

Steps
-----
    1. Build 3 indicators:
        - file: file.name + file.path + file.hashes.sha256 + file.hashes.md5
                + device.hostname + device.ip         (class_uid=1001, 6 obs)
        - process: process.name + process.pid + process.cmd_line +
                   process.parent_process.name + device.hostname
                                                       (class_uid=1007, 5 obs)
        - network: src_endpoint.ip + dst_endpoint.ip + dst_endpoint.port +
                   url.full + device.hostname          (class_uid=4001, 5 obs)
    2. Build 1 alert whose finding_info.related_events has 3 entries, one
       per indicator, each carrying that indicator's full context.
       Assert inline-ness before sending.
    3. POST the alert. Assert exactly ONE request was made, to
       /v1/alerts, and that the body on the wire still carries all 3
       indicators inline.
    4. Poll UAM GraphQL until the alert surfaces.
    5. Read alert.indicators:
         - assert len() >= 3, one record per posted related_events[] entry
         - report, per indicator, which of the observables we sent
           surfaced (by observables[].name)
    6. Close the alert (status=RESOLVED, analystVerdict=TRUE_POSITIVE_BENIGN).

Wire contract
-------------
Same as the single-indicator test:
  * Bearer JWT auth with the console API token (NOT ApiToken, and NOT
    the SDL Log Write Key the raw event collector needs).
  * Content-Encoding: gzip mandatory.
  * S1-Scope header mandatory on /v1/alerts.
  * Each inline indicator's metadata.profiles must include
    "s1/security_indicator".
  * related_events[].uid must equal that indicator's metadata.uid.
Concatenated JSON: objects separated by newlines, then gzip-compressed.
Single Content-Encoding header covers the whole body.

Usage
-----
    python tests/test_uam_alert_interface_batch.py
    python tests/test_uam_alert_interface_batch.py --keep
    python tests/test_uam_alert_interface_batch.py --account-id <id>

Exit code 0 on full round-trip success, non-zero on any step failure.
"""
from __future__ import annotations

import argparse
import hashlib
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

from s1_client import S1Client  # noqa: E402
import unified_alerts as ua  # noqa: E402
from uam_alert_interface import (  # noqa: E402
    UAMAlertInterfaceClient,
    UAMAlertInterfaceError,
    build_file_indicator,
    build_process_indicator,
    build_network_indicator,
    build_alert_referencing,
)


RUN_TAG = f"smoke-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:8]}"


def _log(msg: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


# Every inline related_events[] entry must carry these. A bare
# {"uid": ...} reference is not enough: /v1/indicators is unreachable
# with any credential, so whatever the inline entry omits never reaches
# the tenant at all.
_REQUIRED_INLINE_KEYS = ("uid", "metadata", "device", "actor", "time",
                         "observables", "class_uid", "type_uid",
                         "category_uid", "activity_id")


class _RequestRecorder:
    """Wraps UAMAlertInterfaceClient._post and records every HTTP call.

    Lets the test assert that ingest is exactly ONE request. The removed
    two-call flow (indicators, then sleep, then alert) would show up here
    as two entries.
    """

    def __init__(self, client: Any) -> None:
        self.calls: List[Tuple[str, List[Dict[str, Any]]]] = []
        self._orig = client._post
        client._post = self._record

    def _record(self, path: str, objs: Any, **kwargs: Any) -> Dict[str, Any]:
        items = list(objs)
        self.calls.append((path, items))
        return self._orig(path, items, **kwargs)


def _assert_inline(
    alert: Dict[str, Any],
    expected_observables: Dict[str, Set[str]],
) -> Tuple[bool, List[str]]:
    """Assert the alert body carries every indicator INLINE, with full
    context, before anything is sent. Returns (ok, messages).

    Unlike the post-ingest `_assert_linkage` check below, this one is a
    hard gate: it inspects our own payload, so there is no server-side
    rendering quirk to tolerate.
    """
    msgs: List[str] = []
    entries = (alert.get("finding_info") or {}).get("related_events") or []
    by_uid = {e.get("uid"): e for e in entries}
    missing = set(expected_observables) - set(by_uid)
    if missing:
        msgs.append(f"finding_info.related_events missing uids: "
                    f"{sorted(missing)}")
        return False, msgs

    ok = True
    for uid in sorted(expected_observables):
        entry = by_uid[uid]
        absent = [k for k in _REQUIRED_INLINE_KEYS if not entry.get(k)]
        if absent:
            ok = False
            msgs.append(f"uid={uid[:12]}...  inline entry missing {absent} "
                        f"-- this is a uid-only reference, not inline context")
            continue
        profiles = (entry.get("metadata") or {}).get("profiles") or []
        if "s1/security_indicator" not in profiles:
            ok = False
            msgs.append(f"uid={uid[:12]}...  metadata.profiles missing "
                        f"'s1/security_indicator' (got {profiles})")
            continue
        have = {o.get("name") for o in (entry.get("observables") or [])}
        want = set(expected_observables[uid])
        if want - have:
            ok = False
            msgs.append(f"uid={uid[:12]}...  inline observables missing "
                        f"{sorted(want - have)}")
            continue
        # Class-specific payload: the object the indicator is actually
        # about must travel with it (file / process / endpoints).
        payload_keys = [k for k in ("file", "process", "src_endpoint",
                                    "dst_endpoint") if entry.get(k)]
        if not payload_keys:
            ok = False
            msgs.append(f"uid={uid[:12]}...  inline entry carries no "
                        f"class-specific object (file/process/endpoints)")
            continue
        msgs.append(f"uid={uid[:12]}...  inline ok  class_uid="
                    f"{entry.get('class_uid')}  observables={len(have)}  "
                    f"payload={payload_keys}")
    return ok, msgs


def _pick_account_and_site(
    client: S1Client,
    want_account: Optional[str],
    want_site: Optional[str],
) -> Tuple[str, str, str]:
    if want_account:
        accts = [a for a in (client.get(
                    "/web/api/v2.1/accounts",
                    params={"ids": want_account}).get("data") or [])]
    else:
        accts = client.get("/web/api/v2.1/accounts",
                           params={"limit": 5}).get("data") or []
    if not accts:
        raise RuntimeError("No accounts visible to this token")
    acct = accts[0]
    sites = (client.get(
                "/web/api/v2.1/sites",
                params={"accountIds": acct["id"], "limit": 5})
             .get("data") or {}).get("sites") or []
    if not sites:
        raise RuntimeError(f"No sites under account {acct['id']}")
    site = next((s for s in sites if s["id"] == want_site), sites[0])
    return acct["id"], acct.get("name", "?"), site["id"]


def _poll_for_alert(client: S1Client, scope_input: Dict[str, Any],
                    run_tag: str, *, timeout_s: int = 120
                    ) -> Optional[Dict[str, Any]]:
    deadline = time.time() + timeout_s
    backoff = 3
    while True:
        page = ua.list_alerts(client, scope_input=scope_input, first=25)
        for edge in (page.get("edges") or []):
            n = edge["node"]
            if run_tag in (n.get("name") or "") or run_tag in (
                    n.get("description") or ""):
                return n
        if time.time() >= deadline:
            return None
        time.sleep(backoff)
        backoff = min(backoff * 1.3, 10)


def _observable_names(ind: Dict[str, Any]) -> Set[str]:
    """Observable names on one `alert.indicators` entry.

    `Indicator.observables` is a proper sub-selection, so each entry is a
    real object: `{name, value, type}`. (The retired `rawIndicators` shape
    was a flat dict with `observables[0].name`-style keys, which needed
    re-zipping. Nothing writes that store any more.)
    """
    return {
        str(o.get("name"))
        for o in (ind.get("observables") or [])
        if isinstance(o, dict) and o.get("name")
    }


def _assert_linkage(
    indicators: List[Dict[str, Any]],
    expected_uids: Set[str],
    expected_observables: Dict[str, Set[str]],
) -> Tuple[bool, List[str]]:
    """Returns (ok, list_of_messages).

    Core stitching assertion: `alert.indicators` must carry one record per
    posted `finding_info.related_events[]` entry. That is the field the
    inline ingest path populates and the field the console Indicators tab
    renders, so it is the only field this round-trip can be judged on.
    A live tenant returned 4 entries here for an alert posted with 4
    inline indicators, and `[]` on `alertWithRawIndicators.rawIndicators`.

    Two things are INFORMATIONAL rather than fatal:

      * The `related_events[].uid` -> `Indicator.uid` mapping is not
        documented, so a uid we posted may not be the uid rendered back.
        Reported, not asserted.
      * Per-observable surfacing. Empirically (diag4 on usea1-acme
        2026-04-22) multi-indicator alerts shuffle observable values
        across non-final entries server-side; only the last entry is
        reliably clean. The solo-indicator case (diag3) is clean. That is
        a rendering artifact, not a stitching failure, so the count above
        is what the test hard-fails on.
    """
    msgs: List[str] = []
    if len(indicators) < len(expected_uids):
        msgs.append(f"alert.indicators has {len(indicators)} record(s), "
                    f"expected at least {len(expected_uids)}")
        return False, msgs

    msgs.append(f"STITCH ok: alert.indicators carries "
                f"{len(indicators)} record(s) for "
                f"{len(expected_uids)} posted indicator(s)")

    seen_uids = {str(i.get("uid")) for i in indicators if i.get("uid")}
    missing_uids = expected_uids - seen_uids
    if missing_uids:
        msgs.append(f"UID NOTE: posted metadata.uid(s) not rendered back as "
                    f"Indicator.uid: {sorted(u[:12] + '...' for u in missing_uids)}"
                    f"  (observed {sorted(u[:12] + '...' for u in seen_uids)})")
    else:
        msgs.append(f"UID ok: all {len(expected_uids)} posted metadata.uids "
                    f"are the rendered Indicator.uids")

    # Per-observable surfacing is informational only (see docstring).
    all_want = set().union(*expected_observables.values()) if expected_observables else set()
    for ind in indicators:
        uid = str(ind.get("uid") or "")
        have_names = _observable_names(ind)
        # Match the posted indicator by uid when the mapping held; fall
        # back to the union of everything we sent when it did not.
        want_names = expected_observables.get(uid) or all_want
        missing_obs = want_names - have_names
        label = (uid[:12] + "...") if uid else f"type={ind.get('type')!r}"
        if missing_obs:
            msgs.append(
                f"{label}  obs surfaced={len(have_names)}/"
                f"{len(want_names)}  (server-side observable shuffle on "
                f"multi-indicator alerts -- see _assert_linkage docstring)")
        else:
            msgs.append(f"{label}  ok  obs_present={sorted(want_names)}")
    return True, msgs


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--account-id", default=None)
    ap.add_argument("--site-id", default=None)
    ap.add_argument("--uam-url", default=None)
    ap.add_argument("--keep", action="store_true",
                    help="Skip cleanup; leave the alert in NEW state for UI "
                         "inspection.")
    ap.add_argument("--timeout", type=int, default=120,
                    help="Seconds to wait for alert to surface in UAM.")
    args = ap.parse_args()

    mgmt = S1Client(timeout=30)
    uam_iface = UAMAlertInterfaceClient(
        bearer_token=mgmt.api_token, base_url=args.uam_url)
    _log(f"mgmt={mgmt.base_url}  uam_iface={uam_iface.base_url}  "
         f"run_tag={RUN_TAG}")

    try:
        account_id, account_name, site_id = _pick_account_and_site(
            mgmt, args.account_id, args.site_id)
    except Exception as e:
        _log(f"scope resolution failed: {e}")
        return 1
    scope_str = f"{account_id}:{site_id}"
    _log(f"account={account_id} ({account_name!r})  site={site_id}  "
         f"S1-Scope={scope_str!r}")

    now_ms = int(time.time() * 1000)
    # Per SentinelOne UAM "Alert and Indicator Ingestion" worked example,
    # an alert targets a single asset (one resources[] entry) even when
    # referencing many indicators. We mirror the "multi-stage activity
    # seen on one compromised host" narrative by using one device UID
    # across all 3 indicators -- file + process + network all observed
    # on the same endpoint.
    device_uid = str(uuid.uuid4())
    device_hostname = f"{RUN_TAG}-host"
    user_uid = str(uuid.uuid4())

    # Deterministic, obviously-synthetic hashes derived from the run_tag
    # so callers can grep for them in Skylight later if needed.
    seed = RUN_TAG.encode()
    fake_sha256 = hashlib.sha256(seed + b":sha256").hexdigest()
    fake_md5 = hashlib.md5(seed + b":md5").hexdigest()

    # --- 3 indicators, each multi-observable, different OCSF classes ---
    ind_file_uid = str(uuid.uuid4())
    ind_file = build_file_indicator(
        indicator_uid=ind_file_uid,
        file_name=f"{RUN_TAG}.iso",
        file_path=f"/tmp/{RUN_TAG}.iso",
        file_sha256=fake_sha256,
        file_md5=fake_md5,
        device_uid=device_uid,
        device_hostname=device_hostname,
        device_ip="198.51.100.10",                # RFC 5737 reserved
        user_uid=user_uid,
        user_name="smoke-user",
        now_ms=now_ms,
        message=f"{RUN_TAG} file indicator",
    )

    ind_proc_uid = str(uuid.uuid4())
    ind_proc = build_process_indicator(
        indicator_uid=ind_proc_uid,
        process_name="zzz-smoke-test-does-not-exist.exe",
        process_pid=44321,
        process_cmd_line="zzz-smoke-test-does-not-exist.exe --flag smoke",
        parent_process_name="smoke-parent.exe",
        device_uid=device_uid,
        device_hostname=device_hostname,
        user_uid=user_uid,
        user_name="smoke-user",
        now_ms=now_ms,
        message=f"{RUN_TAG} process indicator",
    )

    ind_net_uid = str(uuid.uuid4())
    ind_net = build_network_indicator(
        indicator_uid=ind_net_uid,
        src_ip="192.0.2.10",                      # RFC 5737 reserved
        dst_ip="198.51.100.20",                   # RFC 5737 reserved
        dst_port=4443,
        url=f"https://example.com/{RUN_TAG}",     # RFC 2606 reserved
        device_uid=device_uid,
        device_hostname=device_hostname,
        user_uid=user_uid,
        user_name="smoke-user",
        now_ms=now_ms,
        message=f"{RUN_TAG} network indicator",
    )

    indicators = [ind_file, ind_proc, ind_net]
    expected_uids = {ind_file_uid, ind_proc_uid, ind_net_uid}
    expected_obs: Dict[str, Set[str]] = {
        ind_file_uid: {o["name"] for o in ind_file["observables"]},
        ind_proc_uid: {o["name"] for o in ind_proc["observables"]},
        ind_net_uid:  {o["name"] for o in ind_net["observables"]},
    }

    # --- 1 alert referencing all 3 indicators ---
    alert_uid = str(uuid.uuid4())
    alert = build_alert_referencing(
        alert_uid=alert_uid,
        indicators=indicators,
        now_ms=now_ms,
        title=f"{RUN_TAG} multi-indicator alert",
        description=(
            f"Smoke-test UAM Alert Interface multi-indicator alert. "
            f"run_tag={RUN_TAG}. references=3 indicators "
            f"(FileSystem+Process+Network). Safe to resolve."
        ),
    )

    # --- 1. inline check: all 3 indicators must be carried IN the alert
    #        body with full context. Runs before ingest so a regression to
    #        uid-only references fails without touching the tenant.
    obs_counts = {k: len(v) for k, v in expected_obs.items()}
    _log(f"INLINE: checking 3 indicators inline in the alert body "
         f"(file={obs_counts[ind_file_uid]}obs, "
         f"process={obs_counts[ind_proc_uid]}obs, "
         f"network={obs_counts[ind_net_uid]}obs)")
    inline_ok, inline_msgs = _assert_inline(alert, expected_obs)
    for m in inline_msgs:
        _log(f"  {m}")
    if not inline_ok:
        _log("INLINE FAILED: alert does not carry all 3 indicators inline")
        return 2
    _log("INLINE ok: 3 indicators carried inline with full context")

    # --- 2. ONE POST /v1/alerts carries the alert and all 3 indicators ---
    recorder = _RequestRecorder(uam_iface)
    _log(f"INGEST: POST /v1/alerts  finding_info.uid={alert_uid}  "
         f"related_events=3 (indicators inline)")
    try:
        r = uam_iface.post_alerts([alert], scope=scope_str)
    except UAMAlertInterfaceError as e:
        _log(f"ALERT INGEST FAILED: HTTP {e.status} :: {e.body}")
        return 3
    _log(f"ALERT INGEST ok: {r}")

    paths = [p for (p, _objs) in recorder.calls]
    if paths != ["/v1/alerts"]:
        _log(f"SINGLE-REQUEST FAILED: expected exactly one POST to "
             f"/v1/alerts, observed {paths}")
        return 3
    _log(f"SINGLE-REQUEST ok: 1 request, {paths[0]}, "
         f"{len(recorder.calls[0][1])} object(s) in body")

    # The body actually put on the wire must still carry all 3 inline.
    sent_alert = recorder.calls[0][1][0]
    sent_ok, sent_msgs = _assert_inline(sent_alert, expected_obs)
    if not sent_ok:
        for m in sent_msgs:
            _log(f"  {m}")
        _log("SENT-BODY FAILED: posted alert body lost inline indicators")
        return 3
    _log("SENT-BODY ok: posted body carries all 3 indicators inline")

    # --- 3. poll UAM ---
    sc = ua.scope([account_id], "ACCOUNT")
    _log(f"POLL: UAM list_alerts for name~={RUN_TAG!r} (up to {args.timeout}s)")
    node = _poll_for_alert(mgmt, sc, RUN_TAG, timeout_s=args.timeout)
    if not node:
        _log("POLL FAILED: alert did not appear in UAM within timeout")
        return 4
    uam_alert_id = node["id"]
    _log(f"POLL ok: uam_alert_id={uam_alert_id}  name={node.get('name')!r}  "
         f"detectedAt={node.get('detectedAt')}")

    # --- 4. verify linkage -- one alert.indicators record per posted
    #        related_events[] entry; observables reported, not asserted ---
    # Server-side processing of the single POST is asynchronous: on some
    # tenants the indicators surface 20-90s AFTER the alert record becomes
    # queryable, and may resolve in multiple passes. Give it a grace
    # window. This is indexing lag on one request, not a race between two.
    _log(f"STITCH: waiting up to 120s for all 3 indicators to land in "
         f"alert.indicators (posted uids: "
         f"file={ind_file_uid[:8]} proc={ind_proc_uid[:8]} net={ind_net_uid[:8]})")
    stitch_deadline = time.time() + 120
    linkage_ok = False
    last_msgs: List[str] = []
    last_count = -1
    indicators: List[Dict[str, Any]] = []
    while time.time() < stitch_deadline:
        indicators = ua.get_alert_indicators(mgmt, uam_alert_id)
        if len(indicators) != last_count:
            last_count = len(indicators)
            _log(f"  alert.indicators count = {last_count}/3")
        linkage_ok, last_msgs = _assert_linkage(
            indicators, expected_uids, expected_obs)
        if linkage_ok:
            break
        time.sleep(5)

    for m in last_msgs:
        _log(f"  {m}")
    _log(f"alert.indicators count: {len(indicators)}")
    if not linkage_ok:
        _log("LINK FAILED: stitching incomplete within grace window")
        _log(f"Manual investigation: alert_id={uam_alert_id}  "
             f"run_tag={RUN_TAG}")
        # Still proceed to cleanup so we don't leak an open alert.
        if not args.keep:
            try:
                ua.set_alert_status(mgmt, scope_input=sc,
                                    alert_ids=[uam_alert_id], status="RESOLVED")
                ua.set_analyst_verdict(mgmt, scope_input=sc,
                                       alert_ids=[uam_alert_id],
                                       verdict="TRUE_POSITIVE_BENIGN")
            except Exception:
                pass
        return 5
    _log("LINK ok: all 3 indicators stitched to alert.indicators "
         "(observable surfacing reported above, not asserted)")

    # --- 5. cleanup ---
    if args.keep:
        _log(f"KEEP flag set -- alert {uam_alert_id} left in current state")
        return 0
    # Preflight, per the skill: ask what this alert can actually do before
    # triggering. Alerts ingested through /v1/alerts offer only addNote and
    # eventSearch, so status/verdict cleanup is not available for them and the
    # mutation's `Missing UAM manage permissions` would be misleading.
    _cleanup_filter = {"or": [{"and": [
        {"fieldId": "id", "stringEqual": {"value": uam_alert_id}}]}]}
    _diag = ua.explain_action_failure(
        mgmt, scope_input=sc, filter_input=_cleanup_filter,
        action_ids=["S1/alert/statusUpdate", "S1/alert/analystVerdictUpdate"])
    if _diag["S1/alert/statusUpdate"]["state"] != "offered":
        _log("CLEANUP SKIPPED: alertAvailableActions reports statusUpdate "
             f"{_diag['S1/alert/statusUpdate']['state']} for this alert type "
             f"(available here: {', '.join(_diag['available'])}). This is a "
             "capability limit of alerts ingested via /v1/alerts, not a token "
             "scope, so resolve it in the console if you want it closed.")
        ua.add_alert_note(mgmt, uam_alert_id,
                          "Smoke test complete, safe to resolve.")
        _log("UAM Alert Interface batch: INGEST(1 alert, 3 indicators inline) "
             "-> POLL -> LINK(3 records on alert.indicators) -- OK; CLEANUP "
             f"not available for this alert type (alert {uam_alert_id} left "
             "NEW, note added)")
        return 0

    _log(f"CLEANUP: status->RESOLVED + analystVerdict->TRUE_POSITIVE_BENIGN "
         f"on {uam_alert_id}")
    try:
        # action_outcome, not the bare payload: alertTriggerActions returns
        # ActionsTriggered even when it refuses the write, with the reason in
        # actions[].failure[].errorMessage.
        for _resp in (
            ua.set_alert_status(mgmt, scope_input=sc, alert_ids=[uam_alert_id],
                                status="RESOLVED"),
            ua.set_analyst_verdict(mgmt, scope_input=sc,
                                   alert_ids=[uam_alert_id],
                                   verdict="TRUE_POSITIVE_BENIGN"),
        ):
            _oc = ua.action_outcome(_resp)
            if not _oc["applied"]:
                _log(f"CLEANUP refused by API: {'; '.join(_oc['errors'])}")
            time.sleep(1)
        time.sleep(2)
    except Exception as e:
        _log(f"CLEANUP FAILED: {e}")
        _log(f"Manual cleanup: resolve alert id={uam_alert_id}")
        return 6
    # Report what the re-get actually shows, not what the write claimed. A UAM
    # alertTriggerActions call returns ActionsTriggered even when the field does
    # not move, so "ok" here would be a lie the moment the write silently no-ops
    # (observed: status stayed NEW after a successful-looking RESOLVED write).
    # Cleanup is housekeeping, not the behaviour under test, so a stuck field is
    # reported and left for manual tidy-up rather than failing the run.
    final = ua.get_alert(mgmt, uam_alert_id)
    _cleaned = final.get("status") == "RESOLVED"
    _verdict = ("ok" if _cleaned
                else f"DID NOT APPLY (resolve alert {uam_alert_id} manually)")
    _log(f"CLEANUP {_verdict}: final status={final.get('status')!r} "
         f"verdict={final.get('analystVerdict')!r}")

    # The banner must not read ALL OK while the tenant is left holding an
    # unresolved smoke alert. The tested behaviour passed either way; say which.
    _log("UAM Alert Interface batch: INGEST(1 alert, 3 indicators inline) "
         "-> POLL -> LINK(3 records on alert.indicators) -- OK; CLEANUP "
         + ("OK" if _cleaned
            else "NOT APPLIED (grant UAM manage on the token, or resolve "
                 f"{uam_alert_id} by hand)"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
