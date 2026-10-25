```python
import csv
import json
import os
import sys
from collections import defaultdict

DATA_DIR = sys.argv[1] if len(sys.argv) > 1 else "dataset"
OUTPUT_FILE = sys.argv[2] if len(sys.argv) > 2 else "output.csv"


def read_csv(filename):
    path = os.path.join(DATA_DIR, filename)

    with open(path, "r", encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def main():
    requests = read_csv("deletion_requests.csv")
    rules = read_csv("deletion_rules.csv")
    identities = read_csv("user_identities.csv")
    activities = read_csv("system_activity.csv")

    audit_path = os.path.join(DATA_DIR, "user_audit_log.csv")
    audits = read_csv("user_audit_log.csv") if os.path.exists(audit_path) else []

    # Resolve current and historical identifiers.
    identity_map = defaultdict(set)

    for row in identities + audits:
        user_id = row.get("user_id", "").strip()

        if not user_id:
            continue

        for key, value in row.items():
            if value and any(word in key.lower()
                             for word in ("email", "phone", "name")):
                identity_map[value.strip().lower()].add(user_id)

    # Index activity records for identity matching.
    activity_index = []

    for activity in activities:
        searchable = " ".join(str(v) for v in activity.values()).lower()
        activity_index.append((activity, searchable))

    # Keep rules available for policy-aware extensions.
    _ = rules

    results = []

    for request in requests:
        case_id = request["case_id"]
        email = request.get("email", "").strip().lower()
        request_text = request.get("request_text", "").lower()

        deletion_requested = any(
            word in request_text
            for word in ("delete", "deletion", "erase", "erasure")
        )

        if not deletion_requested:
            results.append({
                "case_id": case_id,
                "deletion_status": "NOT_APPLICABLE",
                "steps_json": "[]"
            })
            continue

        user_ids = identity_map.get(email, set())
        identifiers = {email}

        for user_id in user_ids:
            identifiers.add(user_id.lower())

        findings = []

        for activity, searchable in activity_index:
            if not any(identifier and identifier in searchable
                       for identifier in identifiers):
                continue

            event_type = activity.get("event_type", "").upper()
            result = activity.get("reported_result", "").upper()

            if event_type in ("RESTORE_BACKUP",):
                operation = "REPORT_RESTORE_RISK"
                state = "ACTIVE"
            elif event_type in (
                "SYNC_RECORD", "INDEX_RECORD",
                "REFRESH_CACHE", "CREATE_EXPORT"
            ):
                operation = "REPORT_ACTIVE_DATA_FLOW"
                state = "ACTIVE"
            elif event_type in (
                "DELETE_RECORD", "REDACT_RECORD",
                "ANONYMIZE_RECORD", "UPDATE_RECORD"
            ) and result != "SUCCESS":
                operation = "REPORT_REMAINING_RECORD"
                state = "PRESENT"
            else:
                continue

            findings.append({
                "step_no": len(findings) + 1,
                "phase": "FINDING",
                "system_id": (
                    activity.get("target_system")
                    or activity.get("source_system")
                    or "unknown_system"
                ),
                "resource_id": (
                    activity.get("resource_id") or "unknown_resource"
                ),
                "operation": operation,
                "state": state,
                "evidence_id": activity.get("activity_id", "")
            })

        # Do not claim deletion is complete without evidence.
        # This is a conservative baseline, not the final policy engine.
        status = "INCOMPLETE"

        results.append({
            "case_id": case_id,
            "deletion_status": status,
            "steps_json": json.dumps(findings, separators=(",", ":"))
        })

    results.sort(key=lambda row: row["case_id"])

    with open(OUTPUT_FILE, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["case_id", "deletion_status", "steps_json"]
        )
        writer.writeheader()
        writer.writerows(results)

    print(f"Generated {OUTPUT_FILE}: {len(results)} cases")


if __name__ == "__main__":
    main()
```
