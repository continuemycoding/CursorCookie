#!/usr/bin/env python3
"""
使用邮箱验证码登录 cursor.com，并以 Cookie-Editor JSON 格式导出 cookie。

输入格式: email----password
示例: SapphiraCaelum5932@outlook.com----rq757721

过 Cloudflare Turnstile 的方式只有一种：CapSolver（见 capsolver_solver.py）。
原先基于真人鼠标轨迹/cliclick 的“过验证”方案已全部移除。
"""

from __future__ import annotations

import argparse
import os
import random
import re
import signal
import sys
import tempfile
import time
from pathlib import Path

# patchright 是经过反检测修补的 Playwright（修复 CDP Runtime.enable 泄露等），
# 用于降低浏览器被 Cloudflare 指纹识别的概率；未安装时回退到原版 playwright。
try:
    from patchright.sync_api import (
        Browser,
        BrowserContext,
        Frame,
        Locator,
        Page,
        sync_playwright,
    )

    _USING_PATCHRIGHT = True
except ImportError:
    from playwright.sync_api import (
        Browser,
        BrowserContext,
        Frame,
        Locator,
        Page,
        sync_playwright,
    )

    _USING_PATCHRIGHT = False

import capsolver_solver
from cookie_export import print_cookie_editor_export
from debug_utils import save_debug
from io_utils import setup_utf8_stdio
from mailbox import MailboxClient

setup_utf8_stdio()

# Cloudflare 拦截页（"Just a moment..." 等）的特征文案，仅用于判断当前是否落在 CF 验证页，
# 真正过验证一律交给 CapSolver（见 capsolver_solver.py）。
_CLOUDFLARE_MARKERS = (
    "just a moment",
    "checking your browser",
    "verify you are human",
    "attention required",
    "cloudflare",
    "cf-turnstile",
    "确认您是真人",
    "before continuing",
    "sure you are human",
)


def is_cloudflare_page(title: str, body: str) -> bool:
    text = f"{title}\n{body}".lower()
    return any(marker in text for marker in _CLOUDFLARE_MARKERS)

LOGIN_URLS = [
    "https://www.cursor.com/api/auth/login",
    "https://authenticator.cursor.sh/",
    "https://authenticate.cursor.sh/",
]

CURSOR_URL = "https://www.cursor.com/"
SETTINGS_URL = "https://www.cursor.com/settings"

EMAIL_SELECTORS = [
    'input[name="email"]',
    'input[type="email"]',
    'input[autocomplete="email"]',
    'input[placeholder*="email" i]',
    'input[placeholder*="邮箱" i]',
]

STEALTH_SCRIPT = """
Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
"""


def log(msg: str) -> None:
    print(msg, flush=True)


def parse_credentials(raw: str) -> tuple[str, str]:
    if "----" not in raw:
        raise ValueError("凭证格式应为: 邮箱----邮箱密码")
    email, password = raw.split("----", 1)
    email = email.strip()
    password = password.strip()
    if not email or not password:
        raise ValueError("邮箱或密码不能为空")
    if "@" not in email:
        raise ValueError(f"邮箱格式无效: {email}")
    return email, password


def get_extension_dir() -> Path | None:
    if os.environ.get("LOAD_COOKIE_EXTENSION", "false").lower() != "true":
        return None

    ext = os.environ.get("COOKIE_EDITOR_DIR", "").strip()
    if not ext:
        return None
    path = Path(ext)
    if path.exists() and (path / "manifest.json").exists():
        return path
    return None


def _extra_browser_args() -> list[str]:
    # 放大窗口：runner 默认窗口太小且不像真实桌面浏览器，是 Turnstile 风控信号之一。
    win_size = os.environ.get("BROWSER_WINDOW_SIZE", "1280,1024")
    args: list[str] = [
        "--window-position=0,0",
        f"--window-size={win_size}",
    ]
    if sys.platform == "linux":
        args.extend(["--no-sandbox", "--disable-dev-shm-usage"])
    extension_dir = get_extension_dir()
    if extension_dir:
        ext_path = str(extension_dir.resolve())
        log(f"[browser] 加载 Cookie-Editor 扩展: {ext_path}")
        args.extend(
            [
                f"--disable-extensions-except={ext_path}",
                f"--load-extension={ext_path}",
            ]
        )
    return args


def launch_browser(playwright) -> tuple[Browser | None, BrowserContext]:
    channel = os.environ.get(
        "PLAYWRIGHT_CHANNEL",
        "chrome" if sys.platform in ("darwin", "win32") else "chromium",
    )
    use_headless = os.environ.get("PLAYWRIGHT_HEADLESS", "false").lower() == "true"
    extra_args = _extra_browser_args()

    log(
        f"[browser] 启动浏览器 (platform={sys.platform}, channel={channel}, "
        f"headless={use_headless}, patchright={_USING_PATCHRIGHT})..."
    )

    if _USING_PATCHRIGHT:
        user_data_dir = os.environ.get("USER_DATA_DIR", "").strip() or tempfile.mkdtemp(
            prefix="cursorcookie-profile-"
        )
        ctx_kwargs: dict = {
            "user_data_dir": user_data_dir,
            "headless": use_headless,
            "timeout": 60_000,
            "no_viewport": True,
            "locale": "en-US",
            "timezone_id": "America/Los_Angeles",
        }
        if channel and channel != "chromium":
            ctx_kwargs["channel"] = channel
        if extra_args:
            ctx_kwargs["args"] = extra_args

        log(f"[browser] patchright 持久化上下文: {user_data_dir}")
        context = playwright.chromium.launch_persistent_context(**ctx_kwargs)
        capsolver_solver.install_hook(context)
        log("[browser] BrowserContext 已创建")
        return None, context

    launch_kwargs: dict = {
        "headless": use_headless,
        "timeout": 60_000,
        "args": ["--disable-blink-features=AutomationControlled", *extra_args],
    }
    if channel and channel != "chromium":
        launch_kwargs["channel"] = channel

    browser = playwright.chromium.launch(**launch_kwargs)
    log("[browser] 浏览器进程已启动")

    context = browser.new_context(
        viewport={"width": 1366, "height": 900},
        locale="en-US",
        timezone_id="America/Los_Angeles",
    )
    context.add_init_script(STEALTH_SCRIPT)
    capsolver_solver.install_hook(context)
    log("[browser] BrowserContext 已创建")
    return browser, context


def iter_frames(page: Page) -> list[Frame]:
    return [page.main_frame, *page.frames]


def find_visible_locator(page: Page, selectors: list[str], timeout_ms: int = 5000) -> Locator | None:
    deadline = time.time() + timeout_ms / 1000
    while time.time() < deadline:
        for frame in iter_frames(page):
            for selector in selectors:
                locator = frame.locator(selector)
                if locator.count() == 0:
                    continue
                try:
                    if locator.first.is_visible():
                        return locator.first
                except Exception:
                    continue
        page.wait_for_timeout(500)
    return None


def solve_turnstile(page: Page, label: str = "", wait_s: int = 8) -> bool:
    """过 Turnstile 的唯一入口：等待 widget 出现并用 CapSolver 求解、注入 token。"""
    return capsolver_solver.solve_when_present(page, label=label, wait_s=wait_s)


def wait_for_page_ready(page: Page, timeout: int = 90) -> None:
    deadline = time.time() + timeout
    last_log = 0.0

    while time.time() < deadline:
        now = time.time()
        if now - last_log >= 10:
            log(f"[login] 等待页面就绪... url={page.url}")
            last_log = now

        title = (page.title() or "").lower()
        body = ""
        try:
            body = page.locator("body").inner_text(timeout=3000).lower()
        except Exception:
            pass

        if is_cloudflare_page(title, body):
            log("[login] 检测到 Cloudflare 验证页，用 CapSolver 求解...")
            solve_turnstile(page, "页面加载", wait_s=10)
            page.wait_for_timeout(2000)
            continue

        if find_visible_locator(page, EMAIL_SELECTORS, timeout_ms=1000):
            return
        if page.locator('[data-index="0"]').count() > 0:
            return

        page.wait_for_timeout(1500)

    raise TimeoutError("页面长时间未加载出登录表单，可能被 Cloudflare 拦截。")


def open_login_page(page: Page) -> None:
    last_error: Exception | None = None

    for url in LOGIN_URLS:
        try:
            log(f"[login] 打开登录入口: {url}")
            page.goto(url, wait_until="domcontentloaded", timeout=120000)
            page.wait_for_timeout(3000)

            if "cursor.com" in page.url and "api/auth/login" not in page.url:
                page.wait_for_timeout(2000)

            wait_for_page_ready(page)
            log(f"[login] 页面就绪: {page.url}")
            return
        except Exception as exc:
            last_error = exc
            log(f"[login] 入口失败 {url}: {exc}")
            save_debug(page, f"login-failed-{LOGIN_URLS.index(url)}")

    save_debug(page, "login-failed-final")
    raise RuntimeError(f"无法打开 Cursor 登录页: {last_error}")


def is_password_url(page: Page) -> bool:
    """仅 URL 含 /password 才算误入密码流程（首页同时有邮箱+密码框不算）。"""
    return "/password" in page.url


def fill_email_field(page: Page, email: str) -> bool:
    email_input = find_visible_locator(page, EMAIL_SELECTORS, timeout_ms=10000)
    if email_input is None:
        return False
    try:
        email_input.click()
        email_input.fill("")
        email_input.fill(email)
    except Exception as exc:
        log(f"[login] 邮箱输入失败: {exc}")
        return False
    log(f"[login] 已输入邮箱（{len(email)} 字符）")
    page.wait_for_timeout(random.randint(300, 600))
    return True


def _locators_for_label(frame: Frame, label: str) -> list[Locator]:
    return [
        frame.get_by_role("button", name=label),
        frame.get_by_role("link", name=label),
        frame.locator(f'button:has-text("{label}")'),
        frame.locator(f'a:has-text("{label}")'),
    ]


def click_button_by_label(page: Page, label: str) -> bool:
    """普通 Playwright 点击：先 locator.click()，失败再 JS click。"""
    for frame in iter_frames(page):
        for loc in _locators_for_label(frame, label):
            try:
                if loc.count() == 0 or not loc.first.is_visible():
                    continue
            except Exception:
                continue
            target = loc.first
            try:
                target.click(timeout=6000)
                log(f"[login] 已点击 {label}")
                page.wait_for_timeout(random.randint(400, 800))
                return True
            except Exception as exc:
                log(f"[login] {label} click 失败，尝试 JS click: {exc}")
                try:
                    target.evaluate("el => el.click()")
                    log(f"[login] 已点击 {label}（JS）")
                    page.wait_for_timeout(random.randint(400, 800))
                    return True
                except Exception as exc2:
                    log(f"[login] {label} JS click 也失败: {exc2}")
    return False


def click_continue_button(page: Page) -> bool:
    clicked = click_button_by_label(page, "Continue")
    if not clicked:
        log("[login] 未找到 Continue 按钮")
    return clicked


def click_email_code_button(page: Page) -> bool:
    if click_button_by_label(page, "Email sign-in code"):
        return True
    log("[login] 未找到 Email sign-in code 按钮")
    return False


def is_on_code_input_page(page: Page) -> bool:
    return page.locator('[data-index="0"]').count() > 0


def safe_body_text(page: Page, timeout_ms: int = 1000) -> str:
    try:
        return page.locator("body").inner_text(timeout=timeout_ms).lower()
    except Exception:
        return ""


def wait_for_code_sent(page: Page, budget: int = 25) -> bool:
    """点击发码后，确认验证码已发出（出现输入框 / 离开 /password / 页面提示已发送）。"""
    start = time.time()
    deadline = start + budget
    last_log = 0.0
    while time.time() < deadline:
        if is_on_code_input_page(page):
            log(f"[login] ✅ 验证码输入框已出现（{time.time() - start:.1f}s）")
            return True
        if not is_password_url(page):
            log(f"[login] ✅ 已离开 /password（{time.time() - start:.1f}s）: {page.url}")
            return True
        body = safe_body_text(page)
        if any(
            k in body
            for k in ("check your email", "verification code", "enter the code", "验证码", "we sent", "sent you a")
        ):
            log(f"[login] ✅ 页面提示已发送验证码（{time.time() - start:.1f}s）")
            return True
        if any(k in body for k in ("can't verify", "verify the user is human")):
            log(f"[login] ❌ bot-check 校验失败提示（{time.time() - start:.1f}s）")
            return False
        now = time.time()
        if now - last_log >= 3:
            log(
                f"[login] 等待发码... {now - start:.1f}s/{budget}s "
                f"url={page.url} body={body.replace(chr(10), ' ')[:70]}"
            )
            last_log = now
        page.wait_for_timeout(500)
    return False


def send_email_code_with_token(page: Page, attempt: int) -> bool:
    """发码核心：求 token → 注入 bot_detection_token → 点 Email sign-in code → 等发码。

    Cursor 的 bot-check 子树在该 CI 浏览器里不会客户端 hydrate（widget 永不渲染），
    所以不走“等 widget→拿回调”，而是直接把合法 token 塞进表单绕过 guard 的 token 检查。
    """
    injected = capsolver_solver.solve_and_inject_bot_token(
        page, label=f"密码页(第{attempt}次)", wait_s=12
    )
    if not injected:
        log(f"[login] 第 {attempt} 次未能注入 bot_detection_token，仍尝试点击发码")

    if not click_email_code_button(page):
        save_debug(page, "email-code-button-missing")
        raise TimeoutError(
            "密码页未找到 Email sign-in code 按钮。请查看 debug/email-code-button-missing.png"
        )
    save_debug(page, f"after-email-code-click-{attempt}")
    return wait_for_code_sent(page, budget=25)


def choose_email_code_login(page: Page) -> None:
    """Submit email 后触发 Email sign-in code 发码（注入 bot_detection_token 绕过 bot-check）。"""
    page.wait_for_timeout(800)

    if is_on_code_input_page(page):
        return

    on_password_page = is_password_url(page) or find_visible_locator(
        page, ['input[type="password"]'], timeout_ms=1500
    )
    if not on_password_page:
        # 邮箱页直出发码入口的情形：同样先备好 token 再点。
        capsolver_solver.solve_and_inject_bot_token(page, label="发码前", wait_s=8)
        if click_email_code_button(page):
            wait_for_code_sent(page, budget=25)
            save_debug(page, "after-email-code-click")
        if is_on_code_input_page(page):
            return
        save_debug(page, "no-code-flow-after-submit")
        log("[login] 提交邮箱后未进入验证码流程，继续等待验证码输入框...")
        return

    log("[login] 进入密码页，准备发码（注入 bot_detection_token 绕过 bot-check）")
    max_attempts = 3
    for attempt in range(1, max_attempts + 1):
        if send_email_code_with_token(page, attempt):
            log("[login] 已进入验证码流程")
            return
        log(f"[login] 第 {attempt}/{max_attempts} 次未发出验证码")
        if attempt < max_attempts:
            log("[login] 刷新页面后重试...")
            try:
                page.reload(wait_until="domcontentloaded", timeout=60000)
                page.wait_for_timeout(random.randint(1200, 2200))
            except Exception as exc:
                log(f"[login] 刷新失败: {exc}")

    save_debug(page, "still-on-password-after-code-click")
    raise TimeoutError(
        "多次尝试发码后仍停留在 /password（bot-check 未通过）。"
        "请查看 debug/still-on-password-after-code-click.png"
    )


def abort_on_password_url(page: Page, phase: str) -> None:
    """等待过程中仍停留在 /password 视为异常，截图后退出，不再操作页面。"""
    label = f"stuck-on-password-{phase}"
    save_debug(page, label)
    raise TimeoutError(
        f"等待过程中仍停留在 /password 页面（phase={phase}）。"
        f"请查看 debug/{label}.png"
    )


def fill_email_and_submit(page: Page, email: str) -> None:
    open_login_page(page)
    wait_for_page_ready(page)

    if not fill_email_field(page, email):
        save_debug(page, "email-input-missing")
        raise TimeoutError("未找到邮箱输入框")

    # Cursor/WorkOS 的邮箱页带隐形 Turnstile，提交前先用 CapSolver 求好 token。
    solve_turnstile(page, "提交邮箱前", wait_s=8)

    log("[login] 点击 Continue 提交邮箱")
    if not click_continue_button(page):
        save_debug(page, "continue-button-missing")
        raise TimeoutError("未找到 Continue 按钮")

    # Continue 后可能出现新的 Turnstile（频繁尝试时尤甚），再求解一次。
    solve_turnstile(page, "提交邮箱后", wait_s=8)

    choose_email_code_login(page)

    log(f"[login] 已提交邮箱，等待验证码输入框: {email}")


def _page_snapshot(page: Page) -> dict:
    title = page.title() or ""
    url = page.url
    body = ""
    try:
        body = page.locator("body").inner_text(timeout=5000)
    except Exception:
        pass
    has_code = page.locator('[data-index="0"]').count() > 0
    return {"title": title, "url": url, "body": body, "has_code": has_code}


def wait_for_login_progress(
    page: Page,
    timeout: int = 90,
    phase: str = "post-submit",
) -> bool:
    deadline = time.time() + timeout
    last_log = 0.0

    while time.time() < deadline:
        now = time.time()
        snap = _page_snapshot(page)

        if snap["has_code"]:
            log(f"[login] ({phase}) 验证码输入框已出现")
            return True

        if "cursor.com" in snap["url"] and "auth" not in snap["url"]:
            log(f"[login] ({phase}) 已进入 cursor.com: {snap['url']}")
            return True

        if page.get_by_text("Account Settings", exact=False).count() > 0:
            log(f"[login] ({phase}) 登录成功，进入 Account Settings")
            return True

        if is_password_url(page):
            abort_on_password_url(page, phase)

        body_lower = snap["body"].lower()
        if any(k in body_lower for k in ("check your email", "verification code", "enter the code", "验证码")):
            log(f"[login] ({phase}) 页面提示已发送验证码，等待输入框渲染...")

        if is_cloudflare_page(snap["title"].lower(), body_lower):
            log(f"[login] ({phase}) 提交后出现 Cloudflare，用 CapSolver 求解...")
            solve_turnstile(page, f"({phase})", wait_s=8)
            page.wait_for_timeout(2000)
            continue

        if now - last_log >= 5:
            preview = snap["body"].replace("\n", " ")[:120]
            remaining = int(deadline - now)
            log(
                f"[login] ({phase}) 等待中... 剩余 {remaining}s "
                f"url={snap['url']} title={snap['title'][:40]} "
                f"code_input={snap['has_code']} body={preview}"
            )
            last_log = now

        page.wait_for_timeout(1500)

    log(f"[login] ({phase}) 等待超时 ({timeout}s)")
    save_debug(page, f"wait-timeout-{phase}")
    return False


def enter_verification_code(page: Page, code: str) -> None:
    if not re.fullmatch(r"\d{6}", code):
        raise ValueError(f"验证码格式错误: {code}")

    log(f"[login] 输入验证码: {code}")
    page.locator('[data-index="0"]').wait_for(state="visible", timeout=30000)

    for index, digit in enumerate(code):
        box = page.locator(f'[data-index="{index}"]')
        box.click()
        box.fill(digit)
        page.wait_for_timeout(random.randint(100, 300))


def login_with_email_code(context: BrowserContext, page: Page, email: str, password: str) -> None:
    mailbox = MailboxClient(email, password)
    mailbox_page = context.new_page()

    fill_email_and_submit(page, email)

    log("[login] 等待验证码输入框（最多 30 秒）...")
    if not wait_for_login_progress(page, timeout=30, phase="code-input"):
        log("[login] 仍未出现验证码框，再等待 10 秒...")
        try:
            page.locator('[data-index="0"]').wait_for(state="visible", timeout=10000)
        except Exception:
            save_debug(page, "code-input-missing")
            raise TimeoutError(
                "提交邮箱后未出现验证码输入框。可能 Cloudflare 未通过或邮箱被拦截。"
                "请查看 debug/code-input-missing.png"
            )

    log("[login] 正在从星辰邮箱大师获取验证码...")
    log(f"[login] 邮箱页面: {mailbox.frontend_url()}")
    try:
        code = mailbox.wait_for_code(timeout=180, interval=8, page=mailbox_page)
    finally:
        mailbox_page.close()

    enter_verification_code(page, code)

    log("[login] 等待登录完成（最多 60 秒）...")
    wait_for_login_progress(page, timeout=60, phase="post-code")
    page.wait_for_timeout(3000)


def export_cursor_cookies(context: BrowserContext, page: Page) -> str:
    log(f"[cookie] 访问 {CURSOR_URL} 读取 cookie...")
    page.goto(CURSOR_URL, wait_until="domcontentloaded", timeout=120000)
    page.wait_for_timeout(3000)

    page.goto(SETTINGS_URL, wait_until="domcontentloaded", timeout=120000)
    page.wait_for_timeout(3000)

    cookies = context.cookies()
    cursor_cookies = [
        c
        for c in cookies
        if "cursor" in (c.get("domain") or "") or "cursor" in (c.get("name") or "").lower()
    ]

    if not cursor_cookies:
        save_debug(page, "cookie-missing")
        raise RuntimeError("未获取到 cursor.com 相关 cookie，登录可能失败。")

    log(f"[cookie] 共获取 {len(cursor_cookies)} 个 cursor 相关 cookie")
    for item in cursor_cookies:
        name = item.get("name", "")
        domain = item.get("domain", "")
        preview = (item.get("value") or "")[:24]
        log(f"  - {name} @ {domain} = {preview}...")

    return print_cookie_editor_export(cursor_cookies)


def _install_network_logger(page: Page) -> None:
    """记录 Cloudflare Turnstile 相关网络请求的状态，定位 api.js 是否真的加载。"""

    def _is_cf(url: str) -> bool:
        return "challenges.cloudflare.com" in url or "turnstile" in url

    def on_response(resp) -> None:
        try:
            if _is_cf(resp.url):
                log(f"[net] {resp.status} {resp.url[:110]}")
        except Exception:
            pass

    def on_failed(request) -> None:
        try:
            if _is_cf(request.url):
                log(f"[net] FAILED {request.failure} {request.url[:110]}")
        except Exception:
            pass

    page.on("response", on_response)
    page.on("requestfailed", on_failed)


def _install_cancel_debug_handler(page: Page) -> None:
    def on_cancel(signum: int, _frame) -> None:
        label = "cancelled" if signum == signal.SIGTERM else "interrupted"
        log(f"[debug] 收到终止信号 ({signum})，保存当前页面...")
        save_debug(page, label)
        sys.exit(128 + signum)

    signal.signal(signal.SIGTERM, on_cancel)
    signal.signal(signal.SIGINT, on_cancel)


def run(credentials: str) -> str:
    log("[start] CursorCookie 登录脚本启动")
    email, password = parse_credentials(credentials)
    log(f"[start] 目标邮箱: {email}")

    # 启动即检查 CapSolver 对接情况（Key 有效性 + 余额），方便定位“没对接好”的问题。
    capsolver_solver.log_account()

    with sync_playwright() as playwright:
        log("[browser] Playwright 已初始化")
        browser, context = launch_browser(playwright)
        page = context.pages[0] if context.pages else context.new_page()
        _install_network_logger(page)
        # 把默认超时压到 5s，避免页面跳转/跨域 iframe 未就绪时层层叠加 30s 超时。
        page.set_default_timeout(5000)
        log("[browser] 标签页已就绪（默认超时 5s）")
        _install_cancel_debug_handler(page)

        try:
            login_with_email_code(context, page, email, password)
            return export_cursor_cookies(context, page)
        except Exception:
            save_debug(page, "error")
            raise
        finally:
            context.close()
            if browser is not None:
                browser.close()
            log("[browser] 浏览器已关闭")


def main() -> None:
    log("[boot] Python 进程已启动")
    parser = argparse.ArgumentParser(description="Cursor 邮箱验证码登录并导出 Cookie")
    parser.add_argument(
        "credentials",
        nargs="?",
        default=os.environ.get("ACCOUNT_CREDENTIALS", ""),
        help="格式: 邮箱----密码",
    )
    args = parser.parse_args()

    if not args.credentials:
        print("错误: 请提供凭证，格式为 邮箱----密码", file=sys.stderr)
        print("示例: SapphiraCaelum5932@outlook.com----rq757721", file=sys.stderr)
        sys.exit(1)

    try:
        export_text = run(args.credentials)
        output_file = os.environ.get("COOKIE_OUTPUT_FILE", "cursor-cookies.json")
        Path(output_file).write_text(export_text, encoding="utf-8")
        print(f"[done] Cookie 已写入: {output_file}")
    except Exception as exc:
        print(f"[error] {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
