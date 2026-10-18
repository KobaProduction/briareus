"""Current owner facts for private proofs, without stored entity versions.

These fingerprints are derived from the rows being checked. They are never
incremented, persisted on Team/Project rows, or presented as product versions.
"""

from __future__ import annotations

import hashlib
import json

from projects._persistence import ProjectRow
from teams._persistence import TeamMembershipRow, TeamRow


def _fingerprint(*facts: object) -> int:
    encoded = json.dumps(facts, separators=(",", ":"), default=str).encode()
    return int.from_bytes(hashlib.sha256(encoded).digest(), "big") or 1


def project_state(row: ProjectRow) -> int:
    return _fingerprint(
        "project",
        row.id,
        row.name,
        row.lifecycle_status,
        row.owner_user_id,
        row.owner_team_id,
        row.resource_revision,
    )


def team_state(row: TeamRow) -> int:
    return _fingerprint("team", row.id, row.name, row.owner_user_id, row.resource_revision)


def membership_state(row: TeamMembershipRow) -> int:
    return _fingerprint("membership", row.id, row.team_id, row.user_id, row.active)
