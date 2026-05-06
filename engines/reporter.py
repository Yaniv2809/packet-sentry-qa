import json
from datetime import datetime, timezone


def build_report(results: list) -> dict:
    failed = [r for r in results if not r["passed"]]
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total_assertions": len(results),
            "passed": len(results) - len(failed),
            "failed": len(failed),
        },
        "results": results,
    }


def to_json(report: dict) -> str:
    return json.dumps(report, indent=2)


def build_wireshark_filter(results: list) -> str:
    filters = [
        failure["wireshark_filter"]
        for result in results
        if not result["passed"]
        for failure in result.get("failures", [])
        if "wireshark_filter" in failure
    ]
    return " || ".join(filters)
