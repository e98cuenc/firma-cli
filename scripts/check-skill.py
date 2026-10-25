#!/usr/bin/env python3
"""Checks an Agent Skill's SKILL.md frontmatter against the portable subset of the spec."""
import re
import sys
from pathlib import Path

ALLOWED = {"name", "description", "license", "compatibility", "metadata", "allowed-tools"}

skill = Path(sys.argv[1])
text = (skill / "SKILL.md").read_text(encoding="utf-8")
m = re.match(r"^---\n(.*?)\n---\n", text, re.S)
if not m:
    sys.exit("SKILL.md: missing frontmatter")
fields = dict(line.split(":", 1) for line in m.group(1).splitlines() if line and not line.startswith(" "))
fields = {k.strip(): v.strip() for k, v in fields.items()}
errors = []
if set(fields) - ALLOWED:
    errors.append(f"non-portable fields: {sorted(set(fields) - ALLOWED)}")
name = fields.get("name", "")
if not re.fullmatch(r"[a-z0-9]+(-[a-z0-9]+)*", name) or len(name) > 64:
    errors.append(f"invalid name: {name!r}")
if name != skill.name:
    errors.append(f"name {name!r} does not match directory {skill.name!r}")
desc = fields.get("description", "")
if not 1 <= len(desc) <= 200:
    errors.append(f"description must be 1-200 characters (has {len(desc)})")
if len(text.splitlines()) > 500:
    errors.append("SKILL.md is over 500 lines")
if errors:
    sys.exit("SKILL.md: " + "; ".join(errors))
print(f"{name}: OK ({len(desc)}-character description)")
