from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Vulnerability:
    task_id: int
    bug_title: str
    bug_category: int
    bug_firm_name: str
    domain: str
    bug_type: list[int]
    bug_level: int
    bug_paper: str
    repetition_step: str
    fix_plan: str
    area: list[str]
    industry: str
    bug_display: int = 1
    protocol: bool = True
    bug_url: str = ""
    industry_category: list[str] | None = None
    multipart_files: list[dict[str, Any]] | None = None
    use_whatsai: int = 0
    session_ids: list[str] | None = None
    draft_id: int | None = None
    use_ticket: int = 0

    def to_payload(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "bug_title": self.bug_title,
            "bug_category": self.bug_category,
            "bug_firm_name": self.bug_firm_name,
            "domain": self.domain,
            "bug_type": self.bug_type,
            "bug_level": self.bug_level,
            "bug_paper": self.bug_paper,
            "repetition_step": self.repetition_step,
            "fix_plan": self.fix_plan,
            "area": self.area,
            "industry": self.industry,
            "bug_display": self.bug_display,
            "protocol": self.protocol,
            "bug_url": self.bug_url,
            "industry_category": self.industry_category or [],
            "multipart_files": self.multipart_files or [],
            "use_whatsai": self.use_whatsai,
            "session_ids": self.session_ids or [],
            "draft_id": self.draft_id,
            "use_ticket": self.use_ticket,
        }
