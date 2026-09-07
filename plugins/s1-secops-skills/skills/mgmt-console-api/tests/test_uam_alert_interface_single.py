"""
UAM Alert Interface -- single inline-indicator alert round-trip test -- REVERSIBLE.

Minimum viable happy path. Proves the wire-level contract: one
SecurityAlert carrying one OCSF FileSystem Activity indicator inline is
POSTed in a SINGLE request, and that indicator shows up inside the
alert's `indicators`. For the comprehensive case (multiple observables
per indicator, multiple indicators per alert), see
test_uam_alert_interface_batch.py.

Indicators are never posted separately. /v1/indicators is not reachable
with any credential, so the indicator rides inside the alert body at
`finding_info.related_events[]` with its full OCSF context. That inline
copy is what populates the console Indicators tab.

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
    1. Build the indicator and the alert; assert the alert body carries
       the indicator INLINE (uid + device + actor + metadata +
       observables), not as a bare uid reference.
    2. POST /v1/alerts -> 202 Accepted (gzip + Bearer + S1-Scope). Assert
       that exactly ONE request was made to exactly one path.
    3. Poll UAM GraphQL until the ingested alert surfaces (name filter).
    4. Read alert.indicators, assert the inline indicator surfaced (1
       entry). Indicator surfacing lags the alert record, so this polls.
    5. Cleanup (reversibility): status=RESOLVED, analystVerdict=TRUE_POSITIVE_BENIGN
       via UAM bulk-ops -- ingested alerts are not hard-deletable via public API.

Wire contract quirks (baked in):
  * Auth MUST be `Bearer <JWT>` (the console API token). `ApiToken <JWT>`
    -> HTTP 401. This is NOT the SDL Log Write Key the raw event
    collector needs.
  * Payload MUST be gzip-compressed; Content-Encoding: gzip is mandatory.
  * S1-Scope header is mandatory on /v1/alerts: `<accountId>` or
    `<accountId>:<siteId>`.
  * The inline indicator must carry metadata.profiles =
    ["s1/security_indicator"].

Usage
-----
    python tests/test_uam_alert_interface_single.py
    python tests/test_uam_alert_interface_single.py --keep
    python tests/test_uam_alert_interface_single.py \\
        --account-id <account-id> --site-id <site-id-alt>

Exit code 0 on full round-trip success, non-zero on any step failure.
"""
from __future__ import annotations

import argparse
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

from s1_client import S1Client  # noqa: E402
import unified_alerts as ua  # noqa: E402
from uam_alert_interface import (  # noqa: E402
    UAMAlertInterfaceClient,
    UAMAlertInterfaceError,
    build_file_indicator,
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
    expected_observables: Dict[str, set],
) -> Tuple[bool, List[str]]:
    """Assert the alert body carries each indicator INLINE, with full
    context, before anything is sent. Returns (ok, messages)."""
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
        msgs.append(f"uid={uid[:12]}...  inline ok  "
                    f"observables={len(have)}  context={sorted(k for k in entry if k in _REQUIRED_INLINE_KEYS)}")
    return ok, msgs


def _pick_account_and_site(
    client: S1Client,
    want_account: Optional[str],
    want_site: Optional[str],
) -> tuple[str, str, str]:
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
                    run_tag: str, *, timeout_s: int = 90
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


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--account-id", default=None,
                    help="Target account (default: first visible).")
    ap.add_argument("--site-id", default=None,
                    help="Target site (default: first under account).")
    ap.add_argument("--uam-url", "--igw-url", dest="uam_url", default=None,
                    help="Override UAM Alert Interface base URL. Defaults "
                         "to config.uam_alert_interface_url or the built-in "
                         "prod URL ingest.us1.sentinelone.net.")
    ap.add_argument("--keep", action="store_true",
                    help="Skip cleanup; leave the alert in NEW state.")
    ap.add_argument("--timeout", type=int, default=90,
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
    ind_uid = str(uuid.uuid4())
    alert_uid = str(uuid.uuid4())

    indicator = build_file_indicator(
        indicator_uid=ind_uid,
        file_name=f"{RUN_TAG}.iso",
        device_uid=str(uuid.uuid4()),
        device_hostname=f"{RUN_TAG}-host",
        user_uid=str(uuid.uuid4()),
        now_ms=now_ms,
        message=f"{RUN_TAG} indicator",
    )
    alert = build_alert_referencing(
        alert_uid=alert_uid,
        indicators=[indicator],
        now_ms=now_ms,
        title=f"{RUN_TAG} alert",
        description=f"Smoke-test UAM Alert Interface single-indicator alert. "
                    f"run_tag={RUN_TAG}. Safe to resolve.",
    )

    # --- 1. inline check: the alert body must carry the indicator, not
    #        just point at it. Runs before ingest so a regression to a
    #        uid-only reference fails without touching the tenant.
    expected_obs = {ind_uid: {o["name"] for o in indicator["observables"]}}
    inline_ok, inline_msgs = _assert_inline(alert, expected_obs)
    for m in inline_msgs:
        _log(f"  {m}")
    if not inline_ok:
        _log("INLINE FAILED: alert does not carry the indicator inline")
        return 2

    # --- 2. one POST carries alert + indicator together ---
    recorder = _RequestRecorder(uam_iface)
    _log(f"INGEST: POST /v1/alerts  finding_info.uid={alert_uid}  "
         f"related_events[0].uid={ind_uid} (indicator inline)")
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

    # The body actually put on the wire must carry the indicator inline
    # too, not only the dict we built.
    sent_alert = recorder.calls[0][1][0]
    sent_ok, sent_msgs = _assert_inline(sent_alert, expected_obs)
    if not sent_ok:
        for m in sent_msgs:
            _log(f"  {m}")
        _log("SENT-BODY FAILED: posted alert body lost the inline indicator")
        return 3
    _log("SENT-BODY ok: posted body carries the indicator inline")

    sc = ua.scope([account_id], "ACCOUNT")
    _log(f"POLL: UAM list_alerts for name~={RUN_TAG!r} (up to {args.timeout}s)")
    node = _poll_for_alert(mgmt, sc, RUN_TAG, timeout_s=args.timeout)
    if not node:
        _log("POLL FAILED: alert did not appear in UAM within timeout")
        _log(f"run_tag={RUN_TAG}  alert_uid(finding_info.uid)={alert_uid}")
        return 4
    uam_alert_id = node["id"]
    _log(f"POLL ok: uam_alert_id={uam_alert_id}  name={node.get('name')!r}  "
         f"detectedAt={node.get('detectedAt')}")

    # Server-side processing of the single POST is asynchronous: the
    # indicator can surface on alert.indicators tens of seconds AFTER the
    # alert record itself becomes queryable. Poll rather than read once.
    #
    # alert.indicators is the field the inline path populates and the field
    # the console Indicators tab renders. alertWithRawIndicators.rawIndicators
    # is NOT: it stays [] here, so asserting against it can only fail.
    _log("LINK: waiting up to 120s for the inline indicator to land in "
         "alert.indicators")
    link_deadline = time.time() + 120
    indicators: List[Dict[str, Any]] = []
    last_count = -1
    while True:
        indicators = ua.get_alert_indicators(mgmt, uam_alert_id)
        if len(indicators) != last_count:
            last_count = len(indicators)
            _log(f"  alert.indicators count = {last_count}/1")
        if indicators:
            break
        if time.time() >= link_deadline:
            break
        time.sleep(5)

    seen_uids = [i.get("uid") or "" for i in indicators]
    if not indicators:
        _log("LINK FAILED: alert.indicators is empty -- the inline indicator "
             "never surfaced within the grace window")
        _log(f"Manual investigation: alert_id={uam_alert_id}  "
             f"run_tag={RUN_TAG}  indicator metadata.uid={ind_uid}")
        # Still clean up so we don't leak an open alert.
        if not args.keep:
            try:
                ua.set_alert_status(mgmt, scope_input=sc,
                                    alert_ids=[uam_alert_id], status="RESOLVED")
                ua.set_analyst_verdict(mgmt, scope_input=sc,
                                       alert_ids=[uam_alert_id],
                                       verdict="TRUE_POSITIVE_BENIGN")
            except Exception:
                pass
        return 4
    _log(f"LINK ok: 1 inline indicator surfaced on alert {uam_alert_id} "
         f"(type={indicators[0].get('type')!r} "
         f"title={indicators[0].get('title')!r} "
         f"observables={len(indicators[0].get('observables') or [])})")
    # The related_events[].uid -> Indicator.uid mapping is not documented,
    # so a mismatch is reported and not fatal. The count above is the
    # contract this test enforces.
    if ind_uid in seen_uids:
        _log(f"UID ok: posted metadata.uid={ind_uid[:12]}... is the "
             f"surfaced Indicator.uid")
    else:
        _log(f"UID NOTE: posted metadata.uid={ind_uid[:12]}... is not the "
             f"surfaced Indicator.uid; observed {seen_uids}")

    if args.keep:
        _log(f"KEEP flag set -- leaving alert {uam_alert_id} in current state")
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
             f"(available here: {', '.join(_diag['available'])}). This "
             "caller lacks the UAM permission for this alert type; resolve it "
             "in the console, or grant the service user UAM manage.")
        ua.add_alert_note(mgmt, uam_alert_id,
                          "Smoke test complete, safe to resolve.")
        _log("UAM Alert Interface single: INGEST -> POLL -> LINK -- OK; "
             f"CLEANUP not available for this alert type (alert {uam_alert_id} "
             "left NEW, note added)")
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
        return 5

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
    _log("UAM Alert Interface single: INGEST -> POLL -> LINK -- OK; CLEANUP "
         + ("OK" if _cleaned
            else "NOT APPLIED (grant UAM manage on the token, or resolve "
                 f"{uam_alert_id} by hand)"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
