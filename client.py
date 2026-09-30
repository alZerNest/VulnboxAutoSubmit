from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

import requests


@dataclass(frozen=True)
class SubmitResult:
    ok: bool
    status_code: int
    message: str
    request_id: str = ""
    response: dict[str, Any] | None = None


class VulboxClient:
    def __init__(
        self,
        base_url: str,
        submit_path: str,
        timeout: int = 30,
        auth: dict[str, Any] | None = None,
    ) -> None:
        auth = auth or {}
        configured_token = str(auth.get("token", "")).strip()
        configured_uuid = str(auth.get("uuid", "")).strip()
        configured_cookies = auth.get("cookies", "")

        raw_cookies = os.getenv("VULBOX_COOKIES", "").strip()
        if not raw_cookies and isinstance(configured_cookies, str):
            raw_cookies = configured_cookies.strip()
        cookie_values = self._parse_cookies(raw_cookies)
        token = os.getenv("VULBOX_TOKEN", "").strip() or configured_token or cookie_values.get("vulbox_token", "")
        if not token or token == "在这里粘贴浏览器中的 vulbox_token":
            raise ValueError("请先在 config.yaml 的 auth.token 中填写 vulbox_token")

        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Accept": "application/json, text/plain, */*",
                "Content-Type": "application/json;charset=UTF-8",
                "Authorization": f"Bearer {token}",
                "X-Client-Type": "web",
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/152.0.0.0 Safari/537.36"
                ),
                "Accept-Language": "zh-CN,zh;q=0.9",
                "Origin": base_url.rstrip("/"),
            }
        )
        uuid = os.getenv("VULBOX_UUID", "").strip() or configured_uuid or cookie_values.get("uuid", "")
        if uuid:
            self.session.headers["uuid"] = uuid
        self.session.cookies.set("vulbox_token", token)
        for name, value in cookie_values.items():
            self.session.cookies.set(name, value)
        self.base_url = base_url.rstrip("/")
        self.url = f"{self.base_url}/{submit_path.lstrip('/')}"

    @staticmethod
    def _parse_cookies(raw: str) -> dict[str, str]:
        values = {}
        for item in raw.split(";"):
            name, separator, value = item.strip().partition("=")
            if separator and name:
                values[name] = value
        return values

    def submit(self, payload: dict[str, Any]) -> SubmitResult:
        task_id = payload.get("task_id")
        if task_id is not None:
            self.session.headers["Referer"] = f"{self.base_url}/management/submit/{task_id}"
            try:
                self.session.get(
                    f"{self.base_url}/api/hacker/bugs/tasks/info",
                    params={"id": task_id},
                    timeout=self.timeout,
                )
            except requests.RequestException as exc:
                return SubmitResult(False, 0, f"网络异常: {exc}")

        try:
            response = self.session.post(self.url, json=payload, timeout=self.timeout)
        except requests.RequestException as exc:
            return SubmitResult(False, 0, f"网络异常: {exc}")

        request_id = response.headers.get("X-Request-ID", "")
        try:
            body = response.json()
        except ValueError:
            return SubmitResult(False, response.status_code, "服务端返回非 JSON", request_id)

        ok = (
            response.ok
            and body.get("code") == 200
            and body.get("data", {}).get("result") is True
        )
        message = str(body.get("msg") or body.get("message") or "未知响应")
        if not ok and body.get("data", {}).get("result") is False:
            message = f"{message}: 提交结果为失败"
        return SubmitResult(ok, response.status_code, message, request_id, body)
