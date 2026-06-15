#!/usr/bin/env python3
"""CapSolver 对接：求解 Cloudflare Turnstile（项目唯一的过验证方式）。

严格按官方文档实现：https://docs.capsolver.com/en/guide/captcha/cloudflare_turnstile/

求解三步（全部对应官方 API）：
1. ``getBalance`` 校验 API Key / 余额；
2. ``createTask``（type=``AntiTurnstileTaskProxyLess``，必填 ``websiteURL`` / ``websiteKey``，
   可选 ``metadata.action`` / ``metadata.cdata``，分别对应 Turnstile 元素的
   ``data-action`` / ``data-cdata``）；
3. 轮询 ``getTaskResult`` 直到 ``status == "ready"``，从 ``solution.token`` 取回 token。

拿到 token 后写回页面（Cursor/WorkOS 用的是**隐形 Turnstile**，没有可见复选框）：
- 注入到所有 ``cf-turnstile-response`` 字段（含 Shadow DOM）；
- 触发提前 hook 到的 ``turnstile.render`` 回调，模拟真实校验通过。

仅在设置了 ``CAPSOLVER_API_KEY`` 时启用，所有步骤打印 ``[capsolver]`` 前缀日志。
"""

from __future__ import annotations

import os
import re
import time

import requests

CAPSOLVER_API_BASE = os.environ.get("CAPSOLVER_API_BASE", "https://api.capsolver.com").rstrip("/")

# 在页面脚本执行前 hook：捕获 Turnstile 的 sitekey / action / cdata 与 callback，
# 拿到 CapSolver token 后像真实校验通过那样回调宿主页面。
#
# 关键教训（实测 + 反编译 api.js 验证）：绝不能用 Object.defineProperty 预先定义
# window.turnstile。Cloudflare 的 api.js 用 `("turnstile" in window)` 判断是否“重复导入”，
# 一旦为真就走 "Turnstile already has been loaded" 分支、拒绝把真实实现赋给 window.turnstile，
# 导致它永远 undefined（widget 永不渲染、验证码发不出）。
#
# 正确做法：拦截 window.onloadTurnstileCallback（Cursor 用 ?onload=onloadTurnstileCallback）。
# api.js 先把真实实现赋给 window.turnstile，再（setTimeout 0、并有 1s 重试）调用该 onload
# 回调；我们在调用前把 turnstile.render 包好，于是页面 render() 一定被我们捕获——既不破坏
# api.js 的加载，又能稳拿 sitekey 与真正的 React 回调。另加高频轮询兜底。
TURNSTILE_HOOK_SCRIPT = """
(() => {
  if (window.__cfHookInstalled) return;
  window.__cfHookInstalled = true;
  window.__cfTurnstileCallbacks = window.__cfTurnstileCallbacks || [];
  window.__cfTurnstileParams = window.__cfTurnstileParams || [];

  const record = (container, params) => {
    try {
      if (!params) return;
      let cb = (typeof params.callback === 'function') ? params.callback : null;
      // 隐形 widget 常用容器上的 data-callback 指定回调名，这里一并解析。
      if (!cb && container) {
        let el = null;
        try {
          el = (typeof container === 'string') ? document.querySelector(container) : container;
        } catch (e) {}
        const name = el && el.getAttribute && el.getAttribute('data-callback');
        if (name && typeof window[name] === 'function') cb = window[name];
      }
      window.__cfTurnstileParams.push({
        sitekey: params.sitekey || params.siteKey || '',
        action: params.action || '',
        cdata: params.cData || params.cdata || '',
      });
      if (cb) window.__cfTurnstileCallbacks.push(cb);
    } catch (e) {}
  };

  // 把某个 turnstile 对象的 render 方法包起来（幂等）。
  const wrap = (ts) => {
    try {
      if (!ts || ts.__cfRenderPatched) return ts;
      if (typeof ts.render === 'function') {
        const origRender = ts.render;
        ts.render = function (container, params) {
          record(container, params);
          return origRender.apply(this, arguments);
        };
        ts.__cfRenderPatched = true;
      }
    } catch (e) {}
    return ts;
  };

  // 拦截 onload 回调：调用前先把 render 包好（此时 window.turnstile 已被 api.js 真实赋值）。
  const wrapOnload = (fn) => {
    try {
      if (typeof fn !== 'function' || fn.__cfWrapped) return fn;
      const wrapped = function () {
        try { if (window.turnstile) wrap(window.turnstile); } catch (e) {}
        return fn.apply(this, arguments);
      };
      wrapped.__cfWrapped = true;
      return wrapped;
    } catch (e) { return fn; }
  };

  let _onload = window.onloadTurnstileCallback;
  if (_onload) _onload = wrapOnload(_onload);
  try {
    Object.defineProperty(window, 'onloadTurnstileCallback', {
      configurable: true,
      get() { return _onload; },
      set(v) { _onload = wrapOnload(v); },
    });
  } catch (e) {}

  // 兜底：只读探测 window.turnstile（读操作不会让 "turnstile" in window 变真），
  // 一旦出现就尽快包 render，覆盖非 onload 路径。
  const timer = setInterval(() => {
    try { if (window.turnstile) wrap(window.turnstile); } catch (e) {}
  }, 10);
  setTimeout(() => clearInterval(timer), 120000);
})();
"""

# 拿到 token 后注入页面：穿透 Shadow DOM 写回所有 response 字段，并逐个调用 hook 到的回调。
# 关键：response 字段往往是 React 受控组件，直接 el.value= 不会更新 React 内部 state，
# 必须用原生 value setter 再派发 input 事件（React 的 onChange 才会读到新值）。
TURNSTILE_INJECT_SCRIPT = """
(token) => {
  const sel = 'input[name="cf-turnstile-response"], textarea[name="cf-turnstile-response"],'
            + '#cf-turnstile-response,'
            + 'input[name="g-recaptcha-response"], textarea[name="g-recaptcha-response"],'
            + 'input[name*="turnstile" i], input[name*="captcha" i], input[name*="botcheck" i]';
  let fields = 0;
  const nativeSet = (el, val) => {
    try {
      const proto = el.tagName === 'TEXTAREA'
        ? window.HTMLTextAreaElement.prototype
        : window.HTMLInputElement.prototype;
      const setter = Object.getOwnPropertyDescriptor(proto, 'value').set;
      setter.call(el, val);
    } catch (e) { el.value = val; }
  };
  const visit = (root) => {
    if (!root || !root.querySelectorAll) return;
    root.querySelectorAll(sel).forEach((el) => {
      nativeSet(el, token);
      el.dispatchEvent(new Event('input', { bubbles: true }));
      el.dispatchEvent(new Event('change', { bubbles: true }));
      fields += 1;
    });
    root.querySelectorAll('*').forEach((el) => { if (el.shadowRoot) visit(el.shadowRoot); });
  };
  visit(document);
  let callbacks = 0;
  (window.__cfTurnstileCallbacks || []).forEach((cb) => {
    try { cb(token); callbacks += 1; } catch (e) {}
  });
  return { fields, callbacks };
}
"""

# 读取 hook 捕获的 render 参数（隐形 Turnstile 的 sitekey 来源）。
READ_PARAMS_SCRIPT = "() => (window.__cfTurnstileParams || [])"

# 穿透 Shadow DOM 找 .cf-turnstile / #cf-turnstile / [data-sitekey]（拿 sitekey + action + cdata）。
# 兜底：Cursor/WorkOS 用 render=explicit，容器是 <div id="cf-turnstile"> 且无 data-sitekey，
# sitekey 只存在于 React 注水数据里（siteKey:"0x4..."），所以再 regex 扫一遍整页 HTML。
DETECT_DOM_SCRIPT = """
() => {
  const out = [];
  const visit = (root) => {
    if (!root || !root.querySelectorAll) return;
    root.querySelectorAll('.cf-turnstile, #cf-turnstile, [data-sitekey]').forEach((el) => {
      out.push({
        sitekey: el.getAttribute('data-sitekey') || '',
        action: el.getAttribute('data-action') || '',
        cdata: el.getAttribute('data-cdata') || '',
      });
    });
    root.querySelectorAll('*').forEach((el) => { if (el.shadowRoot) visit(el.shadowRoot); });
  };
  visit(document);
  let found = out.find((x) => x.sitekey) || null;
  if (!found) {
    const html = document.documentElement ? document.documentElement.outerHTML : '';
    const m = html.match(/0x4AAAAAA[A-Za-z0-9_-]{6,}/);
    if (m) found = { sitekey: m[0], action: '', cdata: '' };
  }
  return found;
}
"""

# 诊断脚本：在 widget 检测失败时打印页面真实状态，定位“为什么没渲染/没捕获”。
DIAGNOSE_SCRIPT = """
() => {
  const q = (s) => { try { return !!document.querySelector(s); } catch (e) { return false; } };
  const cont = document.querySelector('#cf-turnstile, .cf-turnstile');
  const html = document.documentElement ? document.documentElement.outerHTML : '';
  const m = html.match(/0x4AAAAAA[A-Za-z0-9_-]{6,}/);
  return {
    hookInstalled: !!window.__cfHookInstalled,
    turnstileType: typeof window.turnstile,
    hasRender: !!(window.turnstile && typeof window.turnstile.render === 'function'),
    onloadType: typeof window.onloadTurnstileCallback,
    scriptPresent: q('#cf-turnstile-script') || q('script[src*="challenges.cloudflare.com"]'),
    paramsCount: (window.__cfTurnstileParams || []).length,
    cbCount: (window.__cfTurnstileCallbacks || []).length,
    containerPresent: !!cont,
    containerChildren: cont ? cont.childElementCount : -1,
    responseInput: q('input[name="cf-turnstile-response"]'),
    contentSitekey: m ? m[0] : '',
    errors: (window.__cfErrors || []).slice(0, 12),
  };
}
"""

# 强制渲染：Cursor 页用 render=explicit + onload=onloadTurnstileCallback，自动浏览器里
# onload 偶尔不触发，导致 turnstile.render 从未被调用（#cf-turnstile 容器空、无 callback）。
# 主动调用 onloadTurnstileCallback() 让页面把真正的 React 回调注册进来（被我们的 hook 捕获）；
# 若连 window.turnstile 都没有（api.js 没加载成功），就重新注入一次 api.js。
KICK_RENDER_SCRIPT = """
() => {
  try {
    const cont = document.querySelector('#cf-turnstile, .cf-turnstile');
    const rendered = (window.__cfTurnstileParams || []).length > 0
      || (cont && cont.childElementCount > 0);
    if (rendered) return 'already-rendered';
    if (typeof window.turnstile === 'undefined') return 'turnstile-undefined';
    // turnstile 已就绪但 widget 没渲染：手动触发页面的 onload 回调（已被 hook 包裹，
    // 会先把 render 包好再渲染），让真正的 React 回调注册进来。
    if (typeof window.onloadTurnstileCallback === 'function') {
      window.onloadTurnstileCallback();
      return 'called-onload';
    }
    return 'no-onload-callback';
  } catch (e) { return 'error:' + (e && e.message); }
}
"""

_SITEKEY_RE = re.compile(r"0x[0-9A-Za-z_-]{20,}")


class CapSolverError(Exception):
    """CapSolver 调用相关错误。"""


def _log(msg: str) -> None:
    print(msg, flush=True)


def is_enabled() -> bool:
    """是否配置了 CapSolver API Key。"""
    return bool(os.environ.get("CAPSOLVER_API_KEY", "").strip())


def _api_key() -> str:
    key = os.environ.get("CAPSOLVER_API_KEY", "").strip()
    if not key:
        raise CapSolverError("未配置 CAPSOLVER_API_KEY")
    return key


def _post(endpoint: str, payload: dict, timeout: int = 30) -> dict:
    resp = requests.post(f"{CAPSOLVER_API_BASE}/{endpoint}", json=payload, timeout=timeout)
    resp.raise_for_status()
    return resp.json()


def log_account() -> None:
    """启动时调用 getBalance 校验 API Key 是否有效、余额是否充足。"""
    if not is_enabled():
        _log("[capsolver] ⚠️ 未配置 CAPSOLVER_API_KEY，CapSolver 已禁用（无法过 Turnstile）")
        return
    key = _api_key()
    masked = f"{key[:6]}...{key[-4:]}" if len(key) > 12 else "***"
    _log(f"[capsolver] API Key 已配置 ({masked})，base={CAPSOLVER_API_BASE}")
    try:
        data = _post("getBalance", {"clientKey": key})
    except Exception as exc:  # noqa: BLE001
        _log(f"[capsolver] ❌ getBalance 请求失败（API 对接异常）: {exc}")
        return
    if data.get("errorId"):
        _log(f"[capsolver] ❌ API Key 无效: {data.get('errorCode')} {data.get('errorDescription')}")
        return
    _log(
        f"[capsolver] ✅ API Key 有效，账户余额=${data.get('balance')} "
        f"packages={len(data.get('packages') or [])}"
    )


# 始终注入：捕获页面 JS 错误（定位 Cloudflare api.js 是否在赋值 window.turnstile 前就抛错），
# 并监听 cf-turnstile api.js 这个 <script> 的 load/error 事件，确认它到底有没有执行。
ERROR_CAPTURE_SCRIPT = """
(() => {
  if (window.__cfErrInstalled) return;
  window.__cfErrInstalled = true;
  window.__cfErrors = [];
  const push = (s) => { try { if (window.__cfErrors.length < 30) window.__cfErrors.push(String(s).slice(0,160)); } catch (e) {} };
  window.addEventListener('error', (e) => {
    if (e && e.target && e.target.tagName === 'SCRIPT') {
      push('SCRIPT-ERROR ' + (e.target.src || '').slice(0,80));
    } else {
      push('ERR ' + (e && e.message || '') + ' @ ' + (e && e.filename || '').slice(0,60));
    }
  }, true);
  window.addEventListener('unhandledrejection', (e) => {
    push('REJ ' + ((e && e.reason && e.reason.message) || (e && e.reason) || ''));
  });
  // 监听 cf-turnstile api.js 脚本的真实 load/error 状态。
  const watch = setInterval(() => {
    try {
      const s = document.getElementById('cf-turnstile-script')
        || document.querySelector('script[src*="challenges.cloudflare.com"]');
      if (s && !s.__cfWatched) {
        s.__cfWatched = true;
        s.addEventListener('load', () => push('CFSCRIPT-LOAD ok'));
        s.addEventListener('error', () => push('CFSCRIPT-ERROR fail'));
      }
    } catch (e) {}
  }, 50);
  setTimeout(() => clearInterval(watch), 30000);
})();
"""


def install_hook(target) -> None:
    """在 BrowserContext 或 Page 上注入 turnstile.render hook（页面脚本执行前生效）。"""
    try:
        target.add_init_script(ERROR_CAPTURE_SCRIPT)
    except Exception:  # noqa: BLE001
        pass
    if os.environ.get("CAPSOLVER_DISABLE_HOOK", "").lower() == "true":
        _log("[capsolver] ⚠️ CAPSOLVER_DISABLE_HOOK=true，跳过 hook 注入（隔离测试用）")
        return
    try:
        target.add_init_script(TURNSTILE_HOOK_SCRIPT)
        _log("[capsolver] 已注入 turnstile.render hook（捕获隐形 widget 的 sitekey/回调）")
    except Exception as exc:  # noqa: BLE001
        _log(f"[capsolver] ❌ 注入 hook 脚本失败: {exc}")


def _eval(frame, script, *args):
    try:
        return frame.evaluate(script, *args)
    except Exception:
        return None


def diagnose(page) -> None:
    """打印页面 Turnstile 真实状态，定位“widget 为何没渲染/没捕获”。"""
    for idx, frame in enumerate([page.main_frame, *page.frames]):
        info = _eval(frame, DIAGNOSE_SCRIPT)
        if not info:
            continue
        # 只打印主文档及包含线索的子 frame，避免刷屏。
        if idx == 0 or info.get("containerPresent") or info.get("contentSitekey"):
            _log(
                f"[capsolver] 诊断 frame#{idx}: turnstile={info.get('turnstileType')} "
                f"render={info.get('hasRender')} onload={info.get('onloadType')} "
                f"script={info.get('scriptPresent')} params={info.get('paramsCount')} "
                f"cb={info.get('cbCount')} container={info.get('containerPresent')}/"
                f"children={info.get('containerChildren')} "
                f"respInput={info.get('responseInput')} "
                f"contentSitekey={info.get('contentSitekey') or '无'} "
                f"errors={info.get('errors') or '无'}"
            )


# 一次性网络探针：从页面所在源直接 fetch api.js，判断 challenges.cloudflare.com
# 到底能不能通 / 返回了什么 / 是否被 CSP 拦执行。
PROBE_APIJS_SCRIPT = """
async () => {
  const out = { csp: '', before: typeof window.turnstile };
  try {
    const meta = document.querySelector('meta[http-equiv="Content-Security-Policy" i]');
    out.csp = meta ? (meta.getAttribute('content') || '').slice(0, 160) : '';
  } catch (e) {}
  // 真正执行一份干净的 api.js（无参数），看 window.turnstile 是否会出现。
  try {
    const ev = await new Promise((res) => {
      const s = document.createElement('script');
      s.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js';
      s.async = true;
      s.onload = () => res('load');
      s.onerror = () => res('error');
      (document.head || document.documentElement).appendChild(s);
      setTimeout(() => res('timeout'), 6000);
    });
    out.scriptEvent = ev;
  } catch (e) { out.scriptEvent = 'exc:' + (e && e.message); }
  await new Promise((r) => setTimeout(r, 2500));
  out.afterTurnstile = typeof window.turnstile;
  out.hasRender = !!(window.turnstile && typeof window.turnstile.render === 'function');
  return out;
}
"""

_probed = False


def probe_apijs(page) -> None:
    """一次性：探测 Cloudflare api.js 是否可加载（仅在 turnstile 始终 undefined 时帮忙定位）。"""
    global _probed
    if _probed:
        return
    _probed = True
    info = _eval(page.main_frame, PROBE_APIJS_SCRIPT)
    if not info:
        _log("[capsolver] 网络探针：执行失败（无返回）")
        return
    _log(
        f"[capsolver] 网络探针：执行干净 api.js -> scriptEvent={info.get('scriptEvent')} "
        f"turnstile {info.get('before')}→{info.get('afterTurnstile')} "
        f"hasRender={info.get('hasRender')} csp={info.get('csp') or '无'}"
    )


def kick_render(page) -> str:
    """主动触发页面渲染 Turnstile（让真正的 React 回调被 hook 捕获）。返回主 frame 结果。"""
    main_result = ""
    for idx, frame in enumerate([page.main_frame, *page.frames]):
        result = _eval(frame, KICK_RENDER_SCRIPT)
        if idx == 0 or (result and result not in ("already-rendered", "no-onload-callback")):
            _log(f"[capsolver] kick frame#{idx}: {result}")
        if idx == 0:
            main_result = result or ""
    return main_result


def detect_turnstile(page) -> dict | None:
    """返回 {sitekey, url, action, cdata} 或 None，并打印检测过程。"""
    frames = [page.main_frame, *page.frames]
    _log(f"[capsolver] 检测 Turnstile：扫描 {len(frames)} 个 frame...")

    # 1) render hook 捕获的参数（隐形 Turnstile 首选，能拿到 action/cdata）
    for frame in frames:
        for params in _eval(frame, READ_PARAMS_SCRIPT) or []:
            if params and params.get("sitekey"):
                params["url"] = page.url
                _log(
                    f"[capsolver] ✅ 从 render hook 捕获 sitekey={params['sitekey']} "
                    f"action={params.get('action') or '无'} cdata={params.get('cdata') or '无'}"
                )
                return params

    # 2) DOM（含 Shadow DOM）上的 data-sitekey
    for frame in frames:
        params = _eval(frame, DETECT_DOM_SCRIPT)
        if params and params.get("sitekey"):
            params["url"] = page.url
            _log(
                f"[capsolver] ✅ 从 DOM 检测到 sitekey={params['sitekey']} "
                f"action={params.get('action') or '无'} cdata={params.get('cdata') or '无'}"
            )
            return params

    # 3) challenges.cloudflare.com iframe 的 URL 中解析 sitekey
    for frame in page.frames:
        url = frame.url or ""
        if "challenges.cloudflare.com" not in url:
            continue
        _log(f"[capsolver] 发现 Cloudflare challenge iframe: {url[:120]}")
        match = _SITEKEY_RE.search(url)
        if match:
            _log(f"[capsolver] ✅ 从 iframe URL 解析到 sitekey={match.group(0)}")
            return {"sitekey": match.group(0), "url": page.url, "action": "", "cdata": ""}

    # 4) 环境变量兜底（手动指定 Cursor 的 Turnstile sitekey）
    override = os.environ.get("CAPSOLVER_SITEKEY", "").strip()
    if override:
        _log(f"[capsolver] ✅ 使用 CAPSOLVER_SITEKEY 指定的 sitekey={override}")
        return {"sitekey": override, "url": page.url, "action": "", "cdata": ""}

    _log("[capsolver] ⚠️ 未在任何 frame 检测到 Turnstile sitekey")
    diagnose(page)
    return None


def solve_turnstile(
    sitekey: str,
    website_url: str,
    *,
    action: str = "",
    cdata: str = "",
    poll_timeout: int = 120,
    poll_interval: float = 3.0,
) -> str:
    """createTask + 轮询 getTaskResult，返回 Turnstile token。

    参数与官方 AntiTurnstileTaskProxyLess 一一对应；轮询按文档 status（ready/processing/idle）处理。
    """
    key = _api_key()

    task: dict = {
        "type": "AntiTurnstileTaskProxyLess",
        "websiteURL": website_url,
        "websiteKey": sitekey,
    }
    metadata = {k: v for k, v in (("action", action), ("cdata", cdata)) if v}
    if metadata:
        task["metadata"] = metadata

    _log(
        f"[capsolver] → createTask sitekey={sitekey} url={website_url} "
        f"metadata={metadata or '无'}"
    )
    data = _post("createTask", {"clientKey": key, "task": task})
    if data.get("errorId"):
        raise CapSolverError(
            f"createTask 失败: {data.get('errorCode')} {data.get('errorDescription')}"
        )
    task_id = data.get("taskId")
    if not task_id:
        raise CapSolverError(f"createTask 未返回 taskId: {data}")
    _log(f"[capsolver] ← createTask 成功 taskId={task_id}，开始轮询结果...")

    start = time.time()
    deadline = start + poll_timeout
    polls = 0
    while time.time() < deadline:
        time.sleep(poll_interval)
        polls += 1
        payload = _post("getTaskResult", {"clientKey": key, "taskId": task_id})
        if payload.get("errorId"):
            raise CapSolverError(
                f"getTaskResult 失败: {payload.get('errorCode')} {payload.get('errorDescription')}"
            )

        status = payload.get("status")
        elapsed = time.time() - start
        if status == "ready":
            token = (payload.get("solution") or {}).get("token", "")
            if not token:
                raise CapSolverError(f"任务完成但未返回 token: {payload}")
            _log(
                f"[capsolver] ✅ 求解成功（{elapsed:.1f}s, {polls} 次轮询），"
                f"token 长度={len(token)} 预览={token[:24]}..."
            )
            return token
        _log(f"[capsolver] 轮询 #{polls} status={status}（已等待 {elapsed:.1f}s）")

    raise CapSolverError(f"轮询超时（{poll_timeout}s）未拿到结果")


def inject_token(page, token: str) -> bool:
    """把 token 写回页面（穿透 Shadow DOM）并触发回调，返回是否成功应用。"""
    total_fields = 0
    total_cbs = 0
    for frame in [page.main_frame, *page.frames]:
        res = _eval(frame, TURNSTILE_INJECT_SCRIPT, token)
        if res:
            total_fields += res.get("fields", 0)
            total_cbs += res.get("callbacks", 0)
    if total_fields or total_cbs:
        _log(f"[capsolver] token 已注入：写入 {total_fields} 个字段，触发 {total_cbs} 个回调")
        return True
    _log("[capsolver] ❌ 未找到可注入的 response 字段/回调（token 无处可用）")
    return False


def solve_when_present(page, *, label: str = "", wait_s: int = 8) -> bool:
    """在 wait_s 秒内轮询等待 Turnstile 出现（隐形 widget 渲染有延迟），出现即求解并注入。

    返回是否成功注入 token。未检测到 Turnstile 返回 False（不算错误）。
    """
    prefix = f"{label} " if label else ""
    if not is_enabled():
        _log(f"[capsolver] {prefix}⚠️ 未配置 CAPSOLVER_API_KEY，跳过求解")
        return False

    deadline = time.time() + wait_s
    attempt = 0
    kicked = False
    while time.time() < deadline:
        attempt += 1
        params = detect_turnstile(page)

        # 检测到 sitekey 但 widget 还没渲染（render=explicit 未触发）→ 主动 kick 一次，
        # 让页面真正调用 turnstile.render，从而把 React 回调注册进 hook，token 才有处可送。
        if not params and not kicked:
            probe_apijs(page)
            result = kick_render(page)
            kicked = True
            if result and result != "already-rendered":
                _log(f"[capsolver] {prefix}尝试触发渲染: {result}，等待 widget 出现...")
                try:
                    page.wait_for_timeout(2500)
                except Exception:
                    time.sleep(2.5)
                params = detect_turnstile(page)

        if params:
            _log(f"[capsolver] {prefix}检测到 Turnstile，开始求解（第 {attempt} 次检测命中）")
            # 求解前确保 widget 已渲染（callback 已注册），否则 token 注入后无回调可触发。
            if not kicked:
                kick_render(page)
                kicked = True
                try:
                    page.wait_for_timeout(1500)
                except Exception:
                    time.sleep(1.5)
            diagnose(page)
            try:
                token = solve_turnstile(
                    params["sitekey"],
                    params["url"],
                    action=params.get("action", ""),
                    cdata=params.get("cdata", ""),
                )
            except (CapSolverError, requests.RequestException) as exc:
                _log(f"[capsolver] {prefix}❌ 求解失败: {exc}")
                return False
            return inject_token(page, token)
        try:
            page.wait_for_timeout(1000)
        except Exception:
            time.sleep(1)

    _log(f"[capsolver] {prefix}{wait_s}s 内未检测到 Turnstile，跳过")
    return False
