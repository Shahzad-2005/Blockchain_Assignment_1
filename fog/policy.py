"""Role-based access-control policy for IIoT resources.

Policy is a two-level map:  role -> resource -> [allowed operations].
Used by the fog node's resource-request handler to decide ALLOW/DENY
*after* identity has already been verified.
"""

POLICY = {
    "temperature-sensor": {"temperature":     ["WRITE", "READ"]},
    "pressure-sensor":    {"pressure":        ["WRITE", "READ"]},
    "valve-controller":   {"valve":           ["WRITE", "READ"],
                            "production-line": ["STOP"]},
    "camera":             {"stream":          ["READ"]},
}


def is_allowed(role: str, resource: str, operation: str) -> bool:
    """Return True if `role` may perform `operation` on `resource`."""
    return operation in POLICY.get(role, {}).get(resource, [])