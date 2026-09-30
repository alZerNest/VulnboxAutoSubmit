from __future__ import annotations

import argparse
import hashlib
import math
from pathlib import Path
from typing import Any

import pandas as pd
import yaml

from client import VulboxClient
from models import Vulnerability


ROOT = Path(__file__).resolve().parent

ALIASES = {
    "project_name": ("project_name", "项目名称"),
    "task_id": ("task_id", "项目ID", "项目id", "project_id"),
    "bug_title": ("bug_title", "漏洞标题"),
    "bug_category": ("bug_category", "漏洞类别"),
    "bug_firm_name": ("bug_firm_name", "vendor", "厂商信息", "厂商名称"),
    "domain": ("domain", "所属域名", "厂商域名"),
    "bug_type": ("bug_type", "漏洞类型"),
    "bug_level": ("bug_level", "漏洞等级"),
    "bug_url": ("bug_url", "漏洞url/位置", "漏洞URL/位置"),
    "bug_paper": ("bug_paper", "bug_description", "漏洞简述"),
    "repetition_step": ("repetition_step", "bug_content", "复现步骤"),
    "fix_plan": ("fix_plan", "bug_repair", "修复方案", "修复建议"),
    "area": ("area", "所属地区"),
    "industry": ("industry", "所属行业"),
    "industry_category": ("industry_category", "行业细分"),
    "bug_parameter": ("bug_parameter", "影响参数"),
    "bug_poc": ("bug_poc", "漏洞POC请求包"),
}

CATEGORY_VALUES = {
    "事件型": 1,
    "事件型漏洞": 1,
    "通用型": 2,
    "通用型漏洞": 2,
}

LEVEL_VALUES = {
    "严重": 4,
    "高危": 3,
    "中危": 2,
    "低危": 1,
}

REQUIRED_FIELDS = {
    "project_name": "项目名称",
    "task_id": "项目ID",
    "bug_title": "漏洞标题",
    "bug_category": "漏洞类别",
    "bug_firm_name": "厂商名称",
    "domain": "厂商域名",
    "bug_type": "漏洞类型",
    "bug_level": "漏洞等级",
    "bug_paper": "漏洞简述",
    "repetition_step": "复现步骤",
    "fix_plan": "修复建议",
    "area": "所属地区",
    "industry": "所属行业",
}


def is_blank(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, float) and math.isnan(value):
        return True
    return str(value).strip() == ""


def first_value(row: dict[str, Any], field: str, default: Any = "") -> Any:
    for name in ALIASES.get(field, (field,)):
        if name in row and not is_blank(row[name]):
            return row[name]
    return default


def row_value(row: dict[str, Any], field: str) -> Any:
    value = first_value(row, field)
    if is_blank(value):
        raise ValueError(f"缺少字段 {REQUIRED_FIELDS.get(field, field)}")
    return value


def text(value: Any) -> str:
    if is_blank(value):
        return ""
    return str(value).replace("\\n", "\n")


def as_int(value: Any, field: str) -> int:
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"字段 {field} 必须是整数") from exc


def enum_int(value: Any, field: str, choices: dict[str, int]) -> int:
    if isinstance(value, str):
        normalized = value.strip()
        if normalized in choices:
            return choices[normalized]
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        options = "、".join(choices)
        raise ValueError(f"字段 {field} 必须填写数字或：{options}") from exc


def as_list(value: Any, field: str) -> list[Any]:
    if isinstance(value, list):
        return value
    if is_blank(value):
        return []
    if isinstance(value, str):
        normalized = value.replace("，", ",").replace("、", ",").replace("/", ",")
        return [item.strip() for item in normalized.split(",") if item.strip()]
    raise ValueError(f"字段 {field} 必须是列表或逗号分隔字符串")


def load_rows(path: Path) -> list[dict[str, Any]]:
    if path.suffix.lower() in {".xlsx", ".xls"}:
        return pd.read_excel(path).to_dict(orient="records")
    if path.suffix.lower() == ".csv":
        return pd.read_csv(path).to_dict(orient="records")
    raise ValueError("漏洞数据文件只支持 .xlsx、.xls 或 .csv")


def build_vulnerability(row: dict[str, Any], defaults: dict[str, Any]) -> Vulnerability:
    bug_type = [as_int(item, "漏洞类型") for item in as_list(row_value(row, "bug_type"), "漏洞类型")]
    if not bug_type:
        raise ValueError("漏洞类型不能为空")

    return Vulnerability(
        task_id=as_int(row_value(row, "task_id"), "项目ID"),
        bug_title=text(row_value(row, "bug_title")),
        bug_category=enum_int(row_value(row, "bug_category"), "漏洞类别", CATEGORY_VALUES),
        bug_firm_name=text(row_value(row, "bug_firm_name")),
        domain=text(row_value(row, "domain")),
        bug_type=bug_type,
        bug_level=enum_int(row_value(row, "bug_level"), "漏洞等级", LEVEL_VALUES),
        bug_paper=text(row_value(row, "bug_paper")),
        repetition_step=text(row_value(row, "repetition_step")),
        fix_plan=text(row_value(row, "fix_plan")),
        area=[str(item) for item in as_list(row_value(row, "area"), "所属地区")],
        industry=text(row_value(row, "industry")),
        bug_display=as_int(defaults.get("bug_display", 1), "bug_display"),
        protocol=bool(defaults.get("protocol", True)),
        bug_url=text(first_value(row, "bug_url")),
        industry_category=[
            str(item) for item in as_list(first_value(row, "industry_category"), "行业细分")
        ],
        multipart_files=[],
        use_whatsai=as_int(defaults.get("use_whatsai", 0), "use_whatsai"),
        session_ids=[str(item) for item in as_list(defaults.get("session_ids", []), "session_ids")],
        draft_id=defaults.get("draft_id"),
        use_ticket=as_int(defaults.get("use_ticket", 0), "use_ticket"),
    )


def fingerprint(payload: dict[str, Any]) -> str:
    identity = f"{payload['task_id']}|{payload['bug_title']}|{payload['bug_url']}"
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16]


def load_submitted(path: Path) -> set[str]:
    if not path.exists():
        return set()

    submitted = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        parts = line.split("\t", 2)
        if len(parts) >= 2 and parts[1].strip() == "success":
            submitted.add(parts[0].strip())
    return submitted


def record(path: Path, key: str, status: str, title: str) -> None:
    with path.open("a", encoding="utf-8") as handle:
        handle.write(f"{key}\t{status}\t{title[:80]}\n")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Vulbox 漏洞报告自动提交工具")
    parser.add_argument("--data", default="bugs.xlsx", help="漏洞数据文件；默认读取 bugs.xlsx")
    parser.add_argument("--dry-run", action="store_true", help="只预览，不发送提交请求")
    parser.add_argument("--limit", type=int, help="最多提交多少条记录；默认处理数据文件全部记录")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    config_path = ROOT / "config.yaml"
    data_path = ROOT / args.data
    submitted_path = ROOT / "submitted.txt"
    if not config_path.exists():
        raise FileNotFoundError(f"缺少配置文件: {config_path}")
    if not data_path.exists():
        raise FileNotFoundError(f"缺少漏洞数据文件: {data_path}")

    config = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    defaults = config.get("defaults", {})
    rows = load_rows(data_path)
    if not rows:
        print("没有可处理的漏洞记录")
        return 0

    if args.limit is not None:
        rows = rows[: max(args.limit, 0)]

    submitted = load_submitted(submitted_path)
    client = None
    if not args.dry_run:
        client = VulboxClient(
            config.get("api_base_url", "https://user.vulbox.com"),
            config.get("submit_path", "/api/hacker/bugs/bugs"),
            int(config.get("timeout", 30)),
            config.get("auth", {}),
        )

    success = 0
    skipped = 0
    failed = 0
    for index, row in enumerate(rows, start=1):
        try:
            vulnerability = build_vulnerability(row, defaults)
            payload = vulnerability.to_payload()
            key = fingerprint(payload)
            project = text(row_value(row, "project_name"))
            if key in submitted:
                print(f"[{index}] 跳过已成功记录: {project} / {key}")
                skipped += 1
                continue

            print(
                f"[{index}] {'预览' if args.dry_run else '提交'}: "
                f"{project} / {payload['bug_title']} [{key}]"
            )
            if args.dry_run:
                continue

            result = client.submit(payload)
            request_hint = f", request_id={result.request_id}" if result.request_id else ""
            if result.ok:
                print(f"[{index}] 提交成功: {result.message}{request_hint}")
                record(submitted_path, key, "success", payload["bug_title"])
                submitted.add(key)
                success += 1
            else:
                print(f"[{index}] 提交失败: HTTP {result.status_code}, {result.message}{request_hint}")
                record(submitted_path, key, "failed", payload["bug_title"])
                failed += 1
        except (KeyError, TypeError, ValueError, OSError) as exc:
            print(f"[{index}] 数据错误: {exc}")
            failed += 1

    print(f"完成: 成功 {success}，跳过 {skipped}，失败 {failed}，模式 {'dry-run' if args.dry_run else 'submit'}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
