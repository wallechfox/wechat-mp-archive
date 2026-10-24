# -*- coding: utf-8 -*-
"""
微信公众号文章 + 评论导出工具（Web 版）

启动后浏览器打开 http://127.0.0.1:5000 ，在页面上填写：
  1. 微信读书 Cookie（拉取文章列表 + 正文）
  2. 公众号后台 token / fingerprint / Cookie（拉取评论）

数据源：
  文章列表  GET https://weread.qq.com/web/mp/articles?bookId=MP_WXS_xxx&offset=<时间游标>
  文章正文  GET https://weread.qq.com/web/mp/content?reviewId=<bookId>_<originalId>
  评论列表  GET https://mp.weixin.qq.com/misc/appmsgcomment?action=get_unread_appmsg_comment ...
  评论详情  GET https://mp.weixin.qq.com/misc/appmsgcomment?action=list_comment ...

启动：
  pip install -r requirements.txt
  python app.py
"""

import base64
import hashlib
import json
import os
import random
import re
import threading
import time
import urllib.parse
import uuid
import webbrowser
import subprocess
from datetime import datetime
from html import escape, unescape
from html.parser import HTMLParser
from pathlib import Path

import requests
try:
    from urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except Exception:
    pass
from flask import Flask, jsonify, render_template, request

app = Flask(__name__)
SCRIPT_DIR = Path(__file__).resolve().parent
CONFIG_FILE = SCRIPT_DIR / "config.json"
OUTPUT_ROOT = SCRIPT_DIR / "output"

UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36")

WEREAD_HOST = "https://weread.qq.com"
MP_COMMENT_URL = "https://mp.weixin.qq.com/misc/appmsgcomment"
MP_COPYRIGHT_URL = "https://mp.weixin.qq.com/cgi-bin/appmsgcopyright"
# 评论映射本地缓存：同一公众号的 mid -> comment_id 长期稳定（文章不删重发就不会变），
# 缓存后选中导出可直接定位评论，避免逐篇遍历 comment_id 列表。
COMMENT_MAP_CACHE = Path(__file__).resolve().parent / "comment_map_cache.json"

# 读者模式（抓别人公众号精选评论）：mitmproxy 采集微信登录态凭证
MITM_VENV = SCRIPT_DIR / ".mitmvenv"
MITMDUMP = MITM_VENV / "Scripts" / "mitmdump.exe"
MITM_PLUGIN = SCRIPT_DIR / "mitm_cred.py"
READER_CRED_FILE = SCRIPT_DIR / "credentials.json"
READER_ARTICLE_FILE = SCRIPT_DIR / "articles.json"
MITM_PROXY_PORT = 65000
MITM_CA_CER = Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.cer"
MITM_LOG = SCRIPT_DIR / "mitm.log"
MITM_ERR = SCRIPT_DIR / "mitm.err"

# 全局配置与任务状态
CONFIG = {}
TASKS = {}          # task_id -> {status, log:[], result, error}
TASKS_LOCK = threading.Lock()
SEQUENCE = [0]

# 抓取到的数据缓存（当前会话）
CACHE = {"articles": [], "comments": {}, "book_id": "", "mp_name": ""}

# 扫码登录状态（weread=微信读书, mp=公众号后台）
LOGIN_STATE = {
    "weread": {"status": "idle", "message": "", "qrcode": "", "cookie": ""},
    "mp": {"status": "idle", "message": "", "qrcode": "", "token": "", "fingerprint": "", "cookie": ""},
}
LOGIN_LOCK = threading.Lock()

# mitmproxy 采集状态（读者模式）
MITM_STATE = {"running": False, "proc": None, "message": ""}
MITM_LOCK = threading.Lock()


def _set_login(kind: str, status: str, message: str = "", **extra):
    with LOGIN_LOCK:
        s = LOGIN_STATE[kind]
        s["status"] = status
        s["message"] = message
        for k, v in extra.items():
            s[k] = v


def _get_login(kind: str) -> dict:
    with LOGIN_LOCK:
        return dict(LOGIN_STATE[kind])


# ---------------------------------------------------------------------------
# 微信读书扫码登录（纯 HTTP，复用官方 App 扫码协议）
# ---------------------------------------------------------------------------

WEREAD_APP_HEADERS = {
    "User-Agent": "WeRead/7.5.0 (Android; 33; arm64-v8a)",
    "Content-Type": "application/json; charset=UTF-8",
}


def _weread_wx_ticket(sess: requests.Session) -> dict:
    resp = sess.get("https://i.weread.qq.com/wxticket?nonceStr=weread",
                    headers=WEREAD_APP_HEADERS, timeout=10)
    return resp.json()


def _weread_qr_data(sess: requests.Session) -> dict:
    ticket = _weread_wx_ticket(sess)
    params = urllib.parse.urlencode({
        "appid": "wxab9b71ad2b90ff34",
        "noncestr": "weread",
        "timestamp": ticket.get("timeStamp", ""),
        "scope": "snsapi_userinfo,snsapi_timeline,snsapi_friend,snsapi_favorites",
        "signature": ticket.get("signature", ""),
    })
    url = f"https://open.weixin.qq.com/connect/sdk/qrconnect?{params}"
    resp = sess.get(url, headers=WEREAD_APP_HEADERS, timeout=10)
    return resp.json()


def _weread_exchange_token(sess: requests.Session, auth_code: str) -> dict:
    device_id = hashlib.md5(uuid.uuid4().bytes).hexdigest()
    ts = int(time.time() * 1000)
    rand_val = random.randint(0, 999)
    signature = hashlib.sha256(f"{ts}{device_id}{rand_val}".encode()).hexdigest()
    payload = {
        "code": auth_code, "deviceId": device_id, "trackId": "",
        "timestamp": ts, "random": rand_val, "signature": signature,
        "wxToken": 1, "appFirstInstall": 0, "virtualChannelId": "",
        "installId": str(uuid.uuid4()), "isFromQrcode": 1, "isAutoLogout": 0,
        "deviceName": "Android", "deviceType": 1,
    }
    resp = sess.post("https://i.weread.qq.com/login", json=payload,
                     headers=WEREAD_APP_HEADERS, timeout=12)
    return resp.json()


def _weread_poll_worker(uuid_val: str):
    """后台轮询微信扫码授权，成功后把 Cookie 写入 LOGIN_STATE"""
    sess = requests.Session()
    sess.trust_env = False
    poll_url = f"https://long.open.weixin.qq.com/connect/l/qrconnect?f=json&uuid={uuid_val}"
    poll_headers = {"User-Agent": UA}
    start = time.time()
    while time.time() - start < 300:
        try:
            resp = sess.get(poll_url, headers=poll_headers, timeout=28)
            res = resp.json()
            errcode = res.get("wx_errcode") if "wx_errcode" in res else res.get("errcode")
            if errcode == 405:
                info = _weread_exchange_token(sess, res.get("wx_code"))
                vid = info.get("vid")
                if not vid or not info.get("accessToken"):
                    _set_login("weread", "failed", f"换取凭据失败：{info}")
                    return
                skey = info.get("skey") or info.get("accessToken", "")
                refresh = info.get("refreshToken", "")
                cookie = f"wr_vid={vid}; wr_skey={skey}; wr_rt={refresh}"
                user = (info.get("user") or {}).get("name", vid)
                _set_login("weread", "success", f"登录成功：{user}", cookie=cookie)
                return
            elif errcode == 404:
                _set_login("weread", "scanned", "已扫码，请在手机微信上点击确认登录")
            elif errcode in (402, 403):
                _set_login("weread", "expired", "二维码已过期，请重新获取")
                return
        except Exception:
            time.sleep(1)
    _set_login("weread", "expired", "扫码超时，请重新获取")


def start_weread_login() -> dict:
    sess = requests.Session()
    sess.trust_env = False
    qr = _weread_qr_data(sess)
    uuid_val = qr.get("uuid", "")
    if not uuid_val:
        raise RuntimeError("获取二维码失败，未取到 uuid")
    b64 = (qr.get("qrcode") or {}).get("qrcodebase64", "")
    img = f"data:image/jpeg;base64,{b64}" if b64 else f"https://open.weixin.qq.com/connect/qrcode/{uuid_val}"
    _set_login("weread", "scanning", "请使用微信扫码登录微信读书", qrcode=img)
    threading.Thread(target=_weread_poll_worker, args=(uuid_val,), daemon=True).start()
    return {"uuid": uuid_val, "qrcode": img}


# ---------------------------------------------------------------------------
# 公众号后台扫码登录（Playwright 浏览器自动化）
# ---------------------------------------------------------------------------

def _extract_token(page, holder: dict) -> str:
    """登录后从多个来源提取公众号后台 token"""
    if holder.get("token"):
        return holder["token"]
    qs = urllib.parse.parse_qs(urllib.parse.urlparse(page.url).query)
    if qs.get("token"):
        return qs["token"][0]
    try:
        html = page.content()
        m = re.search(r'token=(\d{5,})', html)
        if m:
            return m.group(1)
        m = re.search(r'["\']token["\']\s*[:=]\s*["\']?(\d{5,})', html)
        if m:
            return m.group(1)
    except Exception:
        pass
    for var in ("window.token", "window.__token", "token"):
        try:
            v = page.evaluate(var)
            if v and str(v).strip().isdigit():
                return str(v).strip()
        except Exception:
            pass
    return ""


def _keep_browser(browser, page):
    """登录成功后保留浏览器窗口，直到用户手动关闭。"""
    try:
        while browser.is_connected():
            try:
                page.wait_for_timeout(2000)
            except Exception:
                break
    except Exception:
        pass
    try:
        browser.close()
    except Exception:
        pass


def _mp_login_worker():
    """后台线程：Playwright 有头浏览器打开公众号登录页，等待扫码，提取凭证"""
    from playwright.sync_api import sync_playwright
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=False)  # 有头模式，弹出浏览器窗口供扫码
            ctx = browser.new_context(
                user_agent=("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                            "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"),
                locale="zh-CN",
            )
            page = ctx.new_page()

            holder = {}
            def _on_request(req):
                # 拦截 mp.weixin.qq.com 的所有请求：token 可能出现在任意业务请求 URL 里；
                # fingerprint 只出现在 appmsgcomment 请求里
                try:
                    u = req.url
                    if "mp.weixin.qq.com" not in u:
                        return
                    qs = urllib.parse.parse_qs(urllib.parse.urlparse(u).query)
                    if not holder.get("token") and qs.get("token"):
                        t = (qs["token"][0] or "").strip()
                        if t.isdigit() and len(t) >= 5:
                            holder["token"] = t
                    if "appmsgcomment" in u and not holder.get("fingerprint") and qs.get("fingerprint"):
                        holder["fingerprint"] = qs["fingerprint"][0]
                except Exception:
                    pass
            page.on("request", _on_request)

            page.goto("https://mp.weixin.qq.com/", timeout=40000)
            _set_login("mp", "scanning", "请在弹出的浏览器窗口中使用微信扫码登录")

            # 等待登录完成：URL 跳转 或 cookie 出现 bizuin
            deadline = time.time() + 180
            logged_in = False
            while time.time() < deadline:
                page.wait_for_timeout(2000)
                cookies = ctx.cookies()
                names = {c["name"] for c in cookies}
                if ("bizuin" in names or "data_bizuin" in names) and "slave_sid" in names:
                    logged_in = True
                    break
                if "token=" in page.url and "scanloginqrcode" not in page.url:
                    logged_in = True
                    break
            if not logged_in:
                _set_login("mp", "expired", "扫码超时，请重新获取")
                browser.close()
                return

            _set_login("mp", "scanned", "登录成功，正在提取凭证……")

            # 等页面跳转/加载稳定后再提取
            try:
                page.wait_for_load_state("networkidle", timeout=15000)
            except Exception:
                pass

            # 提取 token（带重试：给页面跳转和多公众号账号选择页留时间）
            token = ""
            for i in range(6):
                token = _extract_token(page, holder)
                if token:
                    break
                _set_login("mp", "scanned",
                           f"正在提取凭证（{i + 1}/6）……若浏览器窗口出现账号选择页，请手动点击要使用的公众号")
                page.wait_for_timeout(3000)

            # 用 token 访问留言管理页，触发 get_unread_appmsg_comment 请求以捕获 fingerprint
            if token:
                try:
                    page.goto(f"https://mp.weixin.qq.com/misc/appmsgcomment?action=list_latest_comment"
                              f"&begin=0&count=10&sendtype=MASSSEND&scene=1&token={token}&lang=zh_CN",
                              timeout=30000)
                    page.wait_for_timeout(4000)
                except Exception:
                    pass

            token = token or holder.get("token", "")
            fingerprint = holder.get("fingerprint", "")
            if not fingerprint:
                try:
                    fingerprint = page.evaluate("window.__fp || window.fingerprint || ''") or ""
                except Exception:
                    pass

            cookies = ctx.cookies()
            cookie_str = "; ".join(f"{c['name']}={c['value']}" for c in cookies)
            # 提取自己的公众号 bizuin → bookId（评论仅对自己的公众号有效）
            bizuin = ""
            for c in cookies:
                if c.get("name") in ("bizuin", "data_bizuin", "slave_bizuin"):
                    bizuin = str(c.get("value", "")).strip()
                    if bizuin:
                        break
            book_id = f"MP_WXS_{bizuin}" if bizuin else ""

            # 提取公众号昵称（用于自动识别当前公众号，避免再手动「解析」）
            nick_name = ""
            try:
                nick_name = page.evaluate(
                    "(window.wx && window.wx.commonData && window.wx.commonData.data "
                    "&& window.wx.commonData.data.nick_name) || ''"
                ) or ""
            except Exception:
                pass

            if not token or not fingerprint:
                if token or fingerprint or cookie_str:
                    # 部分成功：先把已提取到的填入，剩余项提示手动补齐
                    _set_login("mp", "partial",
                               "已自动填入部分凭证" + ("" if fingerprint else "（fingerprint 未抓到，请重试或手动补齐）"),
                               token=token, fingerprint=fingerprint, cookie=cookie_str,
                               book_id=book_id, nick_name=nick_name)
                else:
                    _set_login("mp", "failed", "登录成功但未能提取凭证，请确认公众号有「留言管理」入口（文章需有评论）",
                               book_id=book_id, nick_name=nick_name)
                _keep_browser(browser, page)
                return

            _set_login("mp", "success", "登录成功（浏览器窗口已保留，可自行关闭）",
                       token=token, fingerprint=fingerprint, cookie=cookie_str,
                       book_id=book_id, nick_name=nick_name)
            _keep_browser(browser, page)
    except Exception as e:
        _set_login("mp", "failed", f"公众号后台登录异常：{e}")


def start_mp_login() -> dict:
    _set_login("mp", "starting", "正在启动浏览器，请稍候……")
    threading.Thread(target=_mp_login_worker, daemon=True).start()
    return _get_login("mp")


# ---------------------------------------------------------------------------
# 工具函数
# ---------------------------------------------------------------------------

def sanitize(name: str, mx: int = 80) -> str:
    name = re.sub(r'[\\/*?:"<>|\r\n\t]', "_", (name or "").strip())
    name = re.sub(r"\s+", " ", name).strip()
    return name[:mx].rstrip("._ ") or "article"


def load_config():
    global CONFIG
    if CONFIG_FILE.exists():
        try:
            CONFIG = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
        except Exception:
            CONFIG = {}


def save_config():
    try:
        CONFIG_FILE.write_text(json.dumps(CONFIG, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception:
        pass


def biz_to_book_id(biz: str) -> str:
    if not biz:
        return ""
    b = str(biz).strip()
    if b.startswith("MP_"):
        return b
    raw = urllib.parse.unquote(b).strip()
    raw += "=" * (-len(raw) % 4)
    try:
        decoded = base64.b64decode(raw).decode("utf-8", errors="ignore").strip()
        if decoded.isdigit():
            return f"MP_WXS_{decoded}"
    except Exception:
        pass
    if b.isdigit():
        return f"MP_WXS_{b}"
    return b


def extract_biz_from_html(html: str) -> str:
    for p in (r'__biz=([A-Za-z0-9+/=]{10,})',
              r'var\s+biz\s*=\s*["\']([A-Za-z0-9+/=]{10,})["\']',
              r'window\.__biz\s*=\s*["\']([A-Za-z0-9+/=]{10,})["\']'):
        m = re.search(p, html)
        if m:
            return m.group(1).strip()
    return ""


def extract_meta(html: str, prop: str) -> str:
    m = re.search(rf'<meta\b[^>]*property=["\']{prop}["\'][^>]*content=["\']([^"\']*)["\']', html, re.I)
    if not m:
        m = re.search(rf'<meta\b[^>]*content=["\']([^"\']*)["\'][^>]*property=["\']{prop}["\']', html, re.I)
    return unescape(m.group(1)).strip() if m else ""


def new_task_id() -> str:
    with TASKS_LOCK:
        SEQUENCE[0] += 1
        return f"task_{SEQUENCE[0]}"


class TaskStopped(Exception):
    """任务被用户主动停止（用于拉取/导出中途退出）。"""


def _check_stop(task):
    """若任务被标记停止，抛出 TaskStopped，供各循环中途退出。"""
    if task and task.get("stop"):
        raise TaskStopped()


def _parse_date_ts(s, end: bool = False):
    """把 'YYYY-MM-DD' 转为时间戳；end=True 取当天 23:59:59。解析失败/为空返回 None。"""
    if not s:
        return None
    try:
        dt = datetime.strptime(str(s).strip(), "%Y-%m-%d")
    except Exception:
        return None
    if end:
        dt = dt.replace(hour=23, minute=59, second=59)
    return int(dt.timestamp())


def task_log(task: dict, msg: str):
    line = f"[{datetime.now().strftime('%H:%M:%S')}] {msg}"
    task["log"].append(line)
    print(line, flush=True)


# ---------------------------------------------------------------------------
# 微信读书：文章列表 / 正文
# ---------------------------------------------------------------------------

def _weread_session() -> requests.Session:
    sess = requests.Session()
    sess.trust_env = False
    sess.headers.update({
        "User-Agent": UA,
        "Accept": "application/json, text/plain, */*",
        "Referer": f"{WEREAD_HOST}/",
    })
    return sess


def weread_get(cookie: str, path: str, params=None):
    resp = _weread_session().get(f"{WEREAD_HOST}{path}", params=params,
                                 headers={"Cookie": cookie}, timeout=30)
    resp.raise_for_status()
    return resp.json()


def weread_get_html(cookie: str, path: str, params=None) -> str:
    sess = _weread_session()
    sess.headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    resp = sess.get(f"{WEREAD_HOST}{path}", params=params, headers={"Cookie": cookie}, timeout=40)
    resp.raise_for_status()
    return resp.text


def resolve_book_id(cookie: str, keyword: str):
    keyword = (keyword or "").strip()
    if keyword.startswith("MP_WXS_"):
        return keyword, ""
    if keyword.startswith(("http://", "https://")):
        parsed = urllib.parse.urlparse(keyword)
        qs = urllib.parse.parse_qs(parsed.query)
        if qs.get("__biz"):
            return biz_to_book_id(qs["__biz"][0]), ""
        try:
            sess = _weread_session()
            sess.headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
            resp = sess.get(keyword, headers={"Cookie": cookie}, timeout=30)
            biz = extract_biz_from_html(resp.text)
            if biz:
                return biz_to_book_id(biz), ""
        except Exception:
            pass
        try:
            res = _weread_session().post("https://i.weread.qq.com/mp/getreviewid",
                                         json={"urls": [keyword]}, headers={"Cookie": cookie}, timeout=10).json()
            book_id = res.get("bookId") or ""
            if not book_id and res.get("reviewIds"):
                book_id = res["reviewIds"][0].get("bookId", "")
            if book_id:
                return book_id, ""
        except Exception:
            pass
        raise RuntimeError("无法从该链接解析出公众号 bookId")
    if re.match(r"^[A-Za-z0-9+/=]{10,}$", keyword):
        return biz_to_book_id(keyword), ""
    # 按名称搜索
    try:
        data = weread_get(cookie, "/store/search",
                          {"keyword": urllib.parse.quote(keyword), "scope": "2", "v": "2", "count": "10"})
        for b in data.get("books", []):
            info = b.get("bookInfo", {})
            if info.get("bookId", "").startswith("MP_"):
                return info["bookId"], info.get("title", "")
    except Exception:
        pass
    raise RuntimeError(f"未找到公众号：{keyword}")


def activate_terminal_session(cookie: str, sess: requests.Session = None) -> bool:
    """激活微信读书移动端在线会话，解除 499 / -2041（终端会话未激活）拦截。

    参考 wechat-mp-tools-main 的 weread_signer.activate_terminal_session：
    向 i.weread.qq.com/mobileSync 汇报移动端同步态，把服务端会话通道转为在线活跃态。
    """
    try:
        h = {
            "Cookie": cookie,
            "User-Agent": ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
                           "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"),
            "Content-Type": "application/json; charset=UTF-8",
        }
        s = sess or _weread_session()
        payload = {
            "shelf": 0, "bookInventory": 0, "shelfLecture": 0, "notifications": 0,
            "config": 0, "gift": 0, "payItem": 0, "balance": 0.0, "reviewTimeline": 0,
            "follower": 0, "readingExchange": 0, "chat": 0, "chatRemovedSynckey": 0,
            "wechatFriend": 0, "inBackground": 0, "refluxSynckey": 0, "following": 0,
            "applyList": 0, "mcard": 0, "discoverFeedSynckey": 0, "rateSynckey": 0,
            "browse": 0, "medal": 0, "medalUrl": 0, "regionResource": 0,
            "discoverColumnSynckey": 0, "friendReviewSynckey": 0, "wehearSyncKey": 0,
            "preferTab": 1, "localBrowseTab": "", "localCommunityTab": "",
        }
        resp = s.post("https://i.weread.qq.com/mobileSync", json=payload, headers=h, timeout=10)
        print(f"[TERMINAL SYNC] mobileSync status={resp.status_code}", flush=True)
        s.get("https://i.weread.qq.com/shelf/sync?synckey=0", headers=h, timeout=6)
        s.get("https://i.weread.qq.com/mp/list?listType=0&count=50&synckey=0", headers=h, timeout=6)
        print("[TERMINAL SYNC] 移动端在线会话激活成功", flush=True)
        return True
    except Exception as e:
        print(f"[TERMINAL SYNC ERROR] {e}", flush=True)
        return False


def _flatten_reviews(reviews: list) -> list:
    """把 /web/mp/articles 的 reviews 拍平成文章条目列表，兼容两种返回结构：

    A) 旧版按月份分组嵌套：reviews[].subReviews[].review.mpInfo
    B) 新版扁平：reviews[].mpInfo 或 reviews[].review 或 reviews[] 本身

    每项统一为 dict，字段：title / originalId / reviewId / content / time / readNum / likeNum。
    """
    items = []

    def _mk(*objs):
        """合并多个 dict，后者字段覆盖前者（空值不覆盖）。"""
        out = {}
        for obj in objs:
            if not isinstance(obj, dict):
                continue
            for k, v in obj.items():
                if v or (isinstance(v, (int, float)) and v >= 0 and k in
                         ("time", "readNum", "likeNum", "read_num", "like_num")):
                    out[k] = v
        return out

    for r in reviews:
        if not isinstance(r, dict):
            continue
        subs = r.get("subReviews")
        if isinstance(subs, list) and subs:
            for s in subs:
                if not isinstance(s, dict):
                    continue
                review = s.get("review") if isinstance(s.get("review"), dict) else {}
                mp = review.get("mpInfo") if isinstance(review.get("mpInfo"), dict) else {}
                items.append(_mk(review, mp, s))
            continue
        mp = r.get("mpInfo") if isinstance(r.get("mpInfo"), dict) else {}
        review = r.get("review") if isinstance(r.get("review"), dict) else {}
        items.append(_mk(review, mp, r))
    return items


def fetch_all_articles(cookie: str, book_id: str, task=None, max_articles=0, on_page=None,
                       date_from: str = "", date_to: str = ""):
    """微信读书整号文章列表（/web/mp/articles）。

    关键：offset 是「列表偏移量」（每页返回多少条就递增多少），不是时间戳游标。
    之前误用时间戳当 offset，第二页 offset 越界返回空，导致只拉到第一页 20 篇。
    on_page(articles)：每拉完一页回调一次，用于前端增量渲染。
    date_from/date_to：可选时间范围（YYYY-MM-DD），按 article['time'] 过滤；列表按时间倒序，
    一旦整页都比 date_from 更旧即停止翻页，避免为增量拉取翻完全部历史。
    """
    articles = []
    seen = set()
    offset = 0
    page = 0
    first_data = None  # 第一页响应，用于提取公众号名称
    list_mp_name = ""  # 列表响应里的公众号名称（mpInfo.mp_name，最可靠）
    activated = False  # 是否已尝试激活终端会话（-2041）
    ts_from = _parse_date_ts(date_from)
    ts_to = _parse_date_ts(date_to, end=True)
    while True:
        _check_stop(task)
        page += 1
        try:
            data = weread_get(cookie, "/web/mp/articles", {"bookId": book_id, "offset": offset})
        except requests.HTTPError as e:
            code = e.response.status_code if e.response is not None else "?"
            raise RuntimeError(f"文章列表接口 HTTP {code}，Cookie 可能已过期")
        # 错误码检查（errCode 可能出现在任何一页，不限于第一页）
        err = str(data.get("errCode", data.get("errcode", "")) or "")
        if err:
            # -2041 = 终端会话未激活：自动激活一次后重试
            if not activated and err in ("-2041", "2041"):
                activated = True
                msg = "检测到终端会话未激活(-2041)，正在自动激活移动端会话并重试……"
                if task:
                    task_log(task, msg)
                else:
                    print(f"[fetch_all_articles] {msg}", flush=True)
                activate_terminal_session(cookie)
                time.sleep(1.0)
                page -= 1
                continue
            hint = "（若为 -2041：请在手机「微信读书」App 里打开任意公众号阅读一次以激活）"
            raise RuntimeError(f"文章列表接口返回错误 errCode={err}，请检查 Cookie / 是否触发风控{hint}")
        reviews = data.get("reviews") or []
        if page == 1:
            first_data = data
            if task:
                task_log(task, f"  [debug] 列表响应顶层字段：{list(data.keys())}")
                if reviews and isinstance(reviews[0], dict):
                    task_log(task, f"  [debug] 第一篇分组字段：{list(reviews[0].keys())}")
                    sub = reviews[0].get("subReviews")
                    if isinstance(sub, list) and sub and isinstance(sub[0], dict):
                        s0 = sub[0]
                        rv = s0.get("review") if isinstance(s0.get("review"), dict) else {}
                        mp = rv.get("mpInfo") if isinstance(rv.get("mpInfo"), dict) else {}
                        task_log(task, f"  [debug] 第一篇 subReview 字段：{list(s0.keys())}")
                        task_log(task, f"  [debug] 第一篇 review 字段：{list(rv.keys())}")
                        task_log(task, f"  [debug] 第一篇 mpInfo 字段：{list(mp.keys())}")
        page_items = _flatten_reviews(reviews)
        if not page_items:
            break
        page_times = []
        new_unique = 0   # 本页新增的唯一文章（未见过），用于判断是否翻到底
        new_in_page = 0  # 本页通过时间过滤后实际加入的文章
        for it in page_items:
            title = (it.get("title") or "").strip()
            # 公众号名称：列表响应 mpInfo.mp_name 字段（最可靠，直接取第一篇）
            if not list_mp_name:
                list_mp_name = (it.get("mp_name") or it.get("mpName") or "").strip()
            # originalId 字段名兼容（驼峰/下划线/articleId）
            original_id = (it.get("originalId") or it.get("original_id")
                           or it.get("articleId") or it.get("article_id") or "")
            if not title:
                continue
            key = original_id or title
            if key in seen:
                continue
            seen.add(key)
            new_unique += 1
            # 时间范围过滤（列表按时间倒序，晚于结束日期/早于起始日期的都跳过）
            try:
                it_ts = int(it.get("time") or 0)
            except Exception:
                it_ts = 0
            if it_ts:
                page_times.append(it_ts)
            if ts_from and it_ts and it_ts < ts_from:
                continue
            if ts_to and it_ts and it_ts > ts_to:
                continue
            # reviewId 优先用接口返回的，否则按 {bookId}_{originalId} 拼接
            review_id = (it.get("reviewId") or it.get("review_id")
                         or (f"{book_id}_{original_id}" if original_id else ""))
            articles.append({
                "title": title,
                "original_id": original_id,
                "review_id": review_id,
                "summary": it.get("content") or "",
                "time": it.get("time") or 0,
                "read_num": it.get("readNum") or 0,
                "like_num": it.get("likeNum") or 0,
            })
            new_in_page += 1
        if task:
            task_log(task, f"  文章列表第 {page} 页：本页 {len(page_items)} 条，新增 {new_in_page}，累计 {len(articles)} 篇")
        if on_page:
            on_page(articles)
        # 整页都比起始日期更旧：列表按时间倒序，后续只会更旧，直接停止翻页
        if ts_from and page_times and max(page_times) < ts_from:
            if task:
                task_log(task, "  已到达起始日期，停止翻页")
            break
        if max_articles and len(articles) >= max_articles:
            break
        # 翻页：offset 递增本页原始返回条数（列表偏移量语义）
        offset += len(page_items)
        # 本页没有新增唯一文章（全部重复），说明已到底，避免死循环
        if new_unique == 0:
            break
        if page >= 200:  # 安全上限，防止意外死循环
            break
        time.sleep(0.5)
    # 公众号名称：优先用列表响应里的 mp_name，兜底才走正文 HTML 提取
    mp_name = list_mp_name
    if not mp_name:
        if task:
            task_log(task, "正在获取公众号名称 ...")
        mp_name = _weread_mp_name(cookie, book_id, articles, first_data)
    if task:
        if mp_name:
            task_log(task, f"  公众号名称：{mp_name}")
        else:
            task_log(task, "  [警告] 未能自动识别公众号名称，将显示 bookId")
    return articles, mp_name


def fetch_article_html(cookie: str, review_id: str) -> str:
    rid = urllib.parse.quote(review_id)
    return weread_get_html(cookie, "/web/mp/content", {"reviewId": rid})


def weread_get_ogurl(cookie: str, review_id: str, max_bytes: int = 600_000) -> str:
    """流式读取微信读书正文接口，读到 og:url 即断连（正文响应约 2.6MB，og:url 在前 20KB）。

    返回文章短链（https://mp.weixin.qq.com/s/xxx），失败返回空串。
    """
    if not review_id:
        return ""
    rid = urllib.parse.quote(review_id)
    sess = _weread_session()
    sess.headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    buf = b""
    try:
        with sess.get(f"{WEREAD_HOST}/web/mp/content", params={"reviewId": rid},
                      headers={"Cookie": cookie}, timeout=40, stream=True) as resp:
            resp.raise_for_status()
            for chunk in resp.iter_content(chunk_size=8192):
                if not chunk:
                    continue
                buf += chunk
                if b"og:url" in buf:
                    text = buf.decode("utf-8", "ignore")
                    url = extract_meta(text, "og:url")
                    if url:
                        return url
                if len(buf) >= max_bytes:
                    break
    except Exception:
        return ""
    return ""


def _brief_err(e: Exception) -> str:
    """把异常压成一行可读文案，HTTP 错误带状态码。"""
    if isinstance(e, requests.HTTPError) and e.response is not None:
        return f"HTTP {e.response.status_code}"
    msg = str(e).replace("\n", " ").strip()
    return msg[:120] or e.__class__.__name__


def _diagnose_article_html(raw_html: str) -> str:
    """分析「拿到了 HTML 但没有正文」的原因，返回一句中文说明。"""
    html = raw_html or ""
    low = html.lower()
    if not html.strip():
        return "返回内容为空"
    if ("环境异常" in html or "wappoc_appmsgcaptcha" in low or "去验证" in html
            or "secitptpage/verify" in low):
        return "触发风控验证页"
    if ("该内容已被发布者删除" in html or "此内容因违规无法查看" in html
            or "内容不存在" in html or "该内容已被删除" in html
            or "此内容被多人投诉" in html):
        return "文章已删除或不可见"
    if ('id="js_image_content"' in html or "js_image_wrapper" in html):
        return "图片消息类型，正文不在 js_content"
    if ('id="js_audio_content"' in html or 'id="js_voice"' in html):
        return "语音消息类型，无图文正文"
    if "扫码登录" in html or ("login" in low and "weread" in low and "js_content" not in html):
        return "返回登录/引导页，Cookie 可能失效"
    return f"页面无 js_content（{len(html)} 字节）"


def attach_short_urls(cookie: str, articles: list, task=None, save_path=None) -> int:
    """为文章列表补全短链（og:url），用于正文抓取失败时的直访回退。

    逐篇流式读取 og:url（约 20KB/篇），每篇提取到就按列表顺序重写 txt，中途失败不丢已提取部分。
    返回补全成功的篇数。
    """
    if not articles:
        return 0
    done = 0
    todo = [a for a in articles if not a.get("url") and a.get("review_id")]
    if task:
        task_log(task, f"补全文章短链：{len(todo)} 篇（逐篇读取 og:url，约 1 篇/秒）")
    for i, art in enumerate(todo, 1):
        _check_stop(task)
        url = weread_get_ogurl(cookie, art.get("review_id", ""))
        if url:
            art["url"] = url
            done += 1
        if save_path is not None:
            try:
                lines = [f"{a['title']}\t{a['url']}" for a in articles if a.get("url")]
                if lines:
                    save_path.parent.mkdir(parents=True, exist_ok=True)
                    save_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            except Exception:
                pass
        if task and (i % 20 == 0 or i == len(todo)):
            task_log(task, f"  短链补全进度 {i}/{len(todo)}，成功 {done} 篇")
        time.sleep(0.35)
    if task:
        task_log(task, f"短链补全完成：成功 {done}/{len(todo)} 篇"
                       + (f"，已保存 {save_path}" if save_path is not None and done else ""))
    return done


def _extract_mp_name_from_article_html(html: str) -> str:
    """从公众号文章正文 HTML 提取公众号名称（多种 meta / JS 变量兜底）。"""
    # 1) og:article:author（property）或 name="author"
    name = extract_meta(html, "og:article:author")
    if not name:
        m = re.search(r'<meta\b[^>]*name=["\']author["\'][^>]*content=["\']([^"\']+)["\']', html, re.I)
        if not m:
            m = re.search(r'<meta\b[^>]*content=["\']([^"\']+)["\'][^>]*name=["\']author["\']', html, re.I)
        name = m.group(1).strip() if m else ""
    if name:
        return name
    # 2) JS 变量
    for p in (r'var\s+nickname\s*=\s*["\']([^"\']+)["\']',
              r'profile_nickname\s*=\s*["\']([^"\']+)["\']',
              r'var\s+user_name\s*=\s*["\']([^"\']+)["\']',
              r'nickname\s*[:=]\s*["\']([^"\']+)["\']'):
        m = re.search(p, html)
        if m and m.group(1).strip():
            return m.group(1).strip()
    # 3) id="js_name" 的公众号名元素（a 或 span）
    m = re.search(r'<(?:a|span)[^>]*id="js_name"[^>]*>([^<]+)</(?:a|span)>', html)
    if m:
        return m.group(1).strip()
    # 4) class 含 nickname 的元素内容
    m = re.search(r'<(?:a|span)[^>]*class="[^"]*nickname[^"]*"[^>]*>([^<]+)</(?:a|span)>', html)
    if m:
        return m.group(1).strip()
    return ""


def _weread_mp_name(cookie: str, book_id: str, articles: list, first_data=None) -> str:
    """尽力获取公众号名称：优先列表响应里的名称字段，兜底拉第一篇文章正文提取。"""
    # 1) 列表响应顶层/嵌套字段
    if isinstance(first_data, dict):
        for key in ("nickname", "nickName", "nick_name", "title", "name",
                    "mpName", "accountName", "author"):
            v = first_data.get(key)
            if isinstance(v, str) and v.strip():
                return v.strip()
        for sub in ("mpInfo", "mp_info", "account", "accountInfo"):
            d = first_data.get(sub)
            if isinstance(d, dict):
                for key in ("nickname", "nickName", "title", "name"):
                    v = d.get(key)
                    if isinstance(v, str) and v.strip():
                        return v.strip()
    # 2) 正文 HTML 提取（前 3 篇兜底，避免第一篇 review_id 无效或正文无名称）
    for art in articles[:3]:
        rid = art.get("review_id") or ""
        if not rid:
            continue
        try:
            html = fetch_article_html(cookie, rid)
            name = _extract_mp_name_from_article_html(html)
            if name:
                return name
        except Exception:
            continue
    return ""


def _mp_page_headers(cookie: str) -> dict:
    return {
        "User-Agent": UA,
        "Referer": "https://mp.weixin.qq.com/",
        "Cookie": cookie,
    }


def _extract_cgidata_list(html: str):
    """从「原创」列表页 HTML 解析 window.wx.cgiData 里的 list 数组与 totalcount。

    cgiData 外层混有 '0' * 1 这类 JS 表达式，无法整体 json.loads，
    这里用括号配对精确提取纯 JSON 的 "list": [...] 数组。
    返回 (list, totalcount)。
    """
    total = 0
    m = re.search(r'totalcount\s*:\s*[\'"](\d+)[\'"]', html)
    if m:
        total = int(m.group(1))
    sm = re.search(r'"list"\s*:\s*\[', html)
    if not sm:
        return [], total
    start = sm.end() - 1  # 指向 '['
    depth = 0
    in_str = False
    escape = False
    i = start
    while i < len(html):
        c = html[i]
        if in_str:
            if escape:
                escape = False
            elif c == '\\':
                escape = True
            elif c == '"':
                in_str = False
        else:
            if c == '"':
                in_str = True
            elif c == '[':
                depth += 1
            elif c == ']':
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(html[start:i + 1]), total
                    except Exception:
                        return [], total
        i += 1
    return [], total


def fetch_all_articles_from_mp(cookie: str, token: str, task=None, max_articles=0, on_page=None,
                               date_from: str = "", date_to: str = ""):
    """从公众号后台「原创」列表（appmsgcopyright?action=orignal）分页拉取全部文章。

    只需 token + 后台 Cookie（无需 fingerprint）。返回 (articles, mp_name)。
    articles 每项：title / url(短链接) / msgid / index / create_time / time / reprint_num。
    on_page(articles)：每拉完一页回调一次，用于前端增量渲染。
    date_from/date_to：可选时间范围（YYYY-MM-DD），按 article['time'] 过滤；列表按时间倒序，
    一旦整页都比 date_from 更旧即停止翻页，避免为增量拉取翻完全部历史。
    """
    articles = []
    seen = set()
    mp_name = ""
    begin = 0  # 注意：begin 从 0 开始（第一页是 begin=0），从 1 开始会漏掉第一页 10 篇
    total = 0
    ts_from = _parse_date_ts(date_from)
    ts_to = _parse_date_ts(date_to, end=True)
    while True:
        _check_stop(task)
        params = {
            "action": "orignal",
            "type": "1",
            "begin": str(begin),
            "count": "10",
            "token": token,
            "lang": "zh_CN",
        }
        resp = requests.get(MP_COPYRIGHT_URL, params=params,
                            headers=_mp_page_headers(cookie), timeout=30, verify=False)
        resp.raise_for_status()
        html = resp.text
        if not mp_name:
            m = re.search(r'real_nick_name\s*:\s*"([^"]*)"', html)
            if not m:
                m = re.search(r'nick_name\s*:\s*"([^"]*)"', html)
            mp_name = m.group(1) if m else ""
        lst, total = _extract_cgidata_list(html)
        if not lst:
            break
        page_times = []
        new_unique = 0   # 本页新增的唯一文章（未见过），用于判断是否翻到底
        for it in lst:
            msgid = str(it.get("msgid") or "")
            idx = str(it.get("index") or "")
            key = f"{msgid}_{idx}" if msgid else (it.get("url") or it.get("title") or "")
            if not key or key in seen:
                continue
            seen.add(key)
            new_unique += 1
            # 时间范围过滤（列表按时间倒序，晚于结束日期/早于起始日期的都跳过）
            try:
                it_ts = int(it.get("update_time") or 0)
            except Exception:
                it_ts = 0
            if it_ts:
                page_times.append(it_ts)
            if ts_from and it_ts and it_ts < ts_from:
                continue
            if ts_to and it_ts and it_ts > ts_to:
                continue
            articles.append({
                "title": it.get("title") or "",
                "url": it.get("url") or "",
                "msgid": msgid,
                "index": idx,
                "create_time": it.get("create_time") or "",
                "time": int(it.get("update_time") or 0),
                "reprint_num": it.get("reprint_num") or 0,
            })
        if task:
            task_log(task, f"  原创列表第 {begin} 页：累计 {len(articles)}/{total or '?'} 篇")
        if on_page:
            on_page(articles)
        # 整页都比起始日期更旧：列表按时间倒序，后续只会更旧，直接停止翻页
        if ts_from and page_times and max(page_times) < ts_from:
            if task:
                task_log(task, "  已到达起始日期，停止翻页")
            break
        if max_articles and len(articles) >= max_articles:
            break
        if total and len(articles) >= total:
            break
        if new_unique == 0:  # 本页没有新增唯一文章，避免死循环
            break
        if begin >= 100:  # 安全上限，防止意外死循环
            break
        begin += 1
        time.sleep(0.6)
    return articles, mp_name


def fetch_article_html_direct(url: str) -> str:
    """直接访问公众号文章链接（短链接），返回正文 HTML。"""
    resp = requests.get(url, headers={"User-Agent": UA, "Referer": "https://mp.weixin.qq.com/"},
                        timeout=40, allow_redirects=True, verify=False)
    resp.raise_for_status()
    return resp.text


def extract_content_html(raw_html: str) -> str:
    m = re.search(r'id="js_content"[^>]*>', raw_html)
    if not m:
        return ""
    start = m.end()
    depth = 1
    i = start
    while i < len(raw_html):
        if raw_html[i] == "<":
            if raw_html[i:i + 5] == "</div":
                depth -= 1
                if depth == 0:
                    break
                i += 6
                continue
            if raw_html[i:i + 4] == "<div":
                depth += 1
                i += 4
                continue
        i += 1
    content = raw_html[start:i]
    content = re.sub(r'data-src="([^"]*)"', r'src="\1"', content)
    return content


# ---------------------------------------------------------------------------
# 图片本地化下载
# ---------------------------------------------------------------------------

def _img_ext(url: str) -> str:
    """从图片 URL 猜测扩展名（优先 wx_fmt 参数）。"""
    try:
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
        if "wx_fmt" in qs:
            fmt = qs["wx_fmt"][0][:10]
            if fmt:
                return fmt
        fn = urllib.parse.urlparse(url).path.rsplit("/", 1)[-1].split("?")[0]
        ext = fn.rsplit(".", 1)[-1] if "." in fn else ""
        if 1 <= len(ext) <= 5:
            return ext
    except Exception:
        pass
    return "jpg"


def _download_image(url: str, path: Path) -> bool:
    """下载单个图片资源（带微信 Referer，避免防盗链）。"""
    try:
        resp = requests.get(url, headers={"Referer": "https://mp.weixin.qq.com/",
                                          "User-Agent": UA}, timeout=30, verify=False)
        resp.raise_for_status()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(resp.content)
        return path.stat().st_size > 0
    except Exception:
        return False


def localize_images(content_html: str, media_dir: Path, rel_prefix: str) -> tuple[str, int]:
    """下载正文里的图片到本地，并把 HTML 里的远程 URL 替换为本地相对路径。

    返回 (替换后的 HTML, 成功下载的图片数)。下载失败的图片保持原远程 URL。
    """
    dec = content_html.replace("&amp;", "&")
    urls = set()
    for m in re.finditer(r'(?:data-src|src)="([^"]+)"', dec):
        u = (m.group(1) or "").strip()
        if not u or u.startswith(("data:", "#", "javascript:")):
            continue
        if u.startswith("//"):
            u = "https:" + u
        if not u.startswith(("http://", "https://")):
            continue
        low = u.lower()
        if any(k in low for k in (".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", "wx_fmt", "mmbiz", "qpic")):
            urls.add(u)
    if not urls:
        return content_html, 0

    media_dir.mkdir(parents=True, exist_ok=True)
    url_map = {}
    for i, u in enumerate(sorted(urls), 1):
        fname = f"img_{i:03d}.{_img_ext(u)}"
        if _download_image(u, media_dir / fname):
            url_map[u] = f"{rel_prefix}/{fname}"

    if not url_map:
        return content_html, 0

    localized = content_html
    for orig, local in url_map.items():
        for v in {orig, orig.replace("&", "&amp;")}:
            localized = localized.replace(v, local)
    return localized, len(url_map)


# ---------------------------------------------------------------------------
# HTML -> Markdown
# ---------------------------------------------------------------------------

class HTMLToMarkdownParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.pieces = []
        self.list_stack = []
        self.in_pre = False
        self.in_code = False
        self.in_blockquote = False
        self.blockquote_depth = 0
        self.in_table = False
        self.table_data = []
        self.current_row = []
        self.current_cell = []
        self.link_stack = []
        self.bold_depth = 0
        self.italic_depth = 0
        self.strike_depth = 0
        self.heading_level = 0
        self.heading_text = []

    def handle_starttag(self, tag, attrs):
        attr_dict = dict(attrs)
        tag = tag.lower()
        if tag in ('h1', 'h2', 'h3', 'h4', 'h5', 'h6'):
            self.heading_level = int(tag[1])
            self.heading_text = []
        elif tag == 'p':
            self._ensure_newline(2)
        elif tag == 'br':
            self.pieces.append('\n')
        elif tag == 'hr':
            self._ensure_newline(2)
            self.pieces.append('---\n\n')
        elif tag in ('strong', 'b'):
            if self.bold_depth == 0:
                self.pieces.append('**')
            self.bold_depth += 1
        elif tag in ('em', 'i'):
            if self.italic_depth == 0:
                self.pieces.append('*')
            self.italic_depth += 1
        elif tag in ('del', 's', 'strike'):
            if self.strike_depth == 0:
                self.pieces.append('~~')
            self.strike_depth += 1
        elif tag == 'code':
            if not self.in_pre:
                self.in_code = True
                self.pieces.append('`')
        elif tag == 'pre':
            self._ensure_newline(2)
            self.in_pre = True
            self.pieces.append('```\n')
        elif tag == 'blockquote':
            self._ensure_newline(2)
            self.blockquote_depth += 1
            self.in_blockquote = True
            self.pieces.append('> ')
        elif tag == 'ul':
            self._ensure_newline(2 if not self.list_stack else 1)
            self.list_stack.append(('ul', 0))
        elif tag == 'ol':
            self._ensure_newline(2 if not self.list_stack else 1)
            self.list_stack.append(('ol', 0))
        elif tag == 'li':
            self._ensure_newline(1)
            indent = '  ' * (len(self.list_stack) - 1) if self.list_stack else ''
            if self.list_stack:
                ltype, count = self.list_stack[-1]
                if ltype == 'ol':
                    count += 1
                    self.list_stack[-1] = (ltype, count)
                    prefix = f'{indent}{count}. '
                else:
                    prefix = f'{indent}- '
            else:
                prefix = '- '
            self.pieces.append(prefix)
        elif tag == 'a':
            href = attr_dict.get('href', '').strip()
            if href and not href.startswith('javascript:') and href != '#':
                self.link_stack.append(href)
                self.pieces.append('[')
            else:
                self.link_stack.append(None)
        elif tag == 'img':
            src = attr_dict.get('src') or attr_dict.get('data-src') or ''
            if src:
                alt = attr_dict.get('alt', '').strip()
                self._ensure_newline(2)
                self.pieces.append(f'![{alt}]({src})\n\n')
        elif tag == 'table':
            self._ensure_newline(2)
            self.in_table = True
            self.table_data = []
        elif tag == 'tr':
            if self.in_table:
                self.current_row = []
        elif tag in ('th', 'td'):
            if self.in_table:
                self.current_cell = []

    def handle_endtag(self, tag):
        tag = tag.lower()
        if tag in ('h1', 'h2', 'h3', 'h4', 'h5', 'h6'):
            level = self.heading_level or 1
            text = ''.join(self.heading_text).strip()
            if text:
                self._ensure_newline(2)
                self.pieces.append(f"{'#' * level} {text}\n\n")
            self.heading_level = 0
            self.heading_text = []
        elif tag == 'p':
            self._ensure_newline(2)
        elif tag in ('strong', 'b'):
            self.bold_depth = max(0, self.bold_depth - 1)
            if self.bold_depth == 0:
                self.pieces.append('**')
        elif tag in ('em', 'i'):
            self.italic_depth = max(0, self.italic_depth - 1)
            if self.italic_depth == 0:
                self.pieces.append('*')
        elif tag in ('del', 's', 'strike'):
            self.strike_depth = max(0, self.strike_depth - 1)
            if self.strike_depth == 0:
                self.pieces.append('~~')
        elif tag == 'code':
            if not self.in_pre:
                self.pieces.append('`')
                self.in_code = False
        elif tag == 'pre':
            self.pieces.append('\n```\n\n')
            self.in_pre = False
        elif tag == 'blockquote':
            self.blockquote_depth = max(0, self.blockquote_depth - 1)
            if self.blockquote_depth == 0:
                self.in_blockquote = False
            self._ensure_newline(2)
        elif tag in ('ul', 'ol'):
            if self.list_stack:
                self.list_stack.pop()
            self._ensure_newline(2)
        elif tag == 'li':
            self._ensure_newline(1)
        elif tag == 'a':
            if self.link_stack:
                href = self.link_stack.pop()
                if href:
                    self.pieces.append(f']({href})')
        elif tag == 'table':
            if self.in_table:
                self.in_table = False
                self._render_table()
                self._ensure_newline(2)
        elif tag == 'tr':
            if self.in_table and self.current_row is not None:
                self.table_data.append(self.current_row)
                self.current_row = []
        elif tag in ('th', 'td'):
            if self.in_table:
                cell_text = ''.join(self.current_cell).strip().replace('|', '\\|').replace('\n', ' ')
                self.current_row.append(cell_text)
                self.current_cell = []

    def handle_data(self, data):
        if self.in_table and self.current_cell is not None:
            self.current_cell.append(data)
            return
        if self.heading_level > 0:
            self.heading_text.append(data)
            return
        if self.in_pre:
            self.pieces.append(data)
            return
        clean_data = data if self.in_code else re.sub(r'[ \t]+', ' ', data)
        if self.in_blockquote:
            clean_data = '\n> '.join(clean_data.split('\n'))
        self.pieces.append(clean_data)

    def _ensure_newline(self, count=1):
        trailing = 0
        idx = len(self.pieces) - 1
        while idx >= 0:
            for ch in reversed(self.pieces[idx]):
                if ch == '\n':
                    trailing += 1
                elif ch in (' ', '\t', '\r'):
                    continue
                else:
                    idx = -1
                    break
            idx -= 1
        needed = count - trailing
        if needed > 0:
            self.pieces.append('\n' * needed)

    def _render_table(self):
        if not self.table_data:
            return
        col_count = max(len(row) for row in self.table_data)
        if col_count == 0:
            return
        for row in self.table_data:
            while len(row) < col_count:
                row.append('')
        header = self.table_data[0]
        rows = self.table_data[1:] if len(self.table_data) > 1 else []
        lines = ['| ' + ' | '.join(header) + ' |',
                 '| ' + ' | '.join(['---'] * col_count) + ' |']
        for r in rows:
            lines.append('| ' + ' | '.join(r) + ' |')
        self.pieces.append('\n' + '\n'.join(lines) + '\n\n')

    def get_markdown(self):
        md = unescape(''.join(self.pieces))
        lines = md.split('\n')
        clean = []
        for line in lines:
            s = line.strip()
            if s:
                clean.append(line.rstrip())
            elif not clean or clean[-1] != "":
                clean.append("")
        return '\n'.join(clean).strip()


def html_to_markdown(content_html: str) -> str:
    cleaned = re.sub(r'<script\b[^>]*>([\s\S]*?)</script>', '', content_html, flags=re.I)
    cleaned = re.sub(r'<style\b[^>]*>([\s\S]*?)</style>', '', cleaned, flags=re.I)
    cleaned = re.sub(r'<noscript\b[^>]*>([\s\S]*?)</noscript>', '', cleaned, flags=re.I)
    cleaned = re.sub(r'<svg\b[^>]*>([\s\S]*?)</svg>', '', cleaned, flags=re.I)
    parser = HTMLToMarkdownParser()
    parser.feed(cleaned)
    return parser.get_markdown()


# ---------------------------------------------------------------------------
# 公众号后台：评论接口
# ---------------------------------------------------------------------------

def _mp_comment_headers(cookie: str) -> dict:
    return {
        "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                       "(KHTML, like Gecko) Chrome/122.0.6261.95 Safari/537.36"),
        "Referer": "https://mp.weixin.qq.com/",
        "X-Requested-With": "XMLHttpRequest",
        "Cookie": cookie,
    }


def _mp_comment_get(cookie: str, params: dict) -> dict:
    params.update({"lang": "zh_CN", "f": "json", "ajax": "1"})
    resp = requests.get(MP_COMMENT_URL, params=params, headers=_mp_comment_headers(cookie),
                        timeout=30, verify=False)
    resp.raise_for_status()
    return resp.json()


def _build_comment_buffer(comment_ids: list) -> str:
    """把已加载的 comment_id 列表编码为 protobuf buffer（field=1, wire_type=0 的 varint 数组）。"""
    out = bytearray()
    for cid in comment_ids:
        v = int(cid)
        out.append(0x08)  # field 1, wire type 0
        while True:
            byte = v & 0x7f
            v >>= 7
            if v:
                out.append(byte | 0x80)
            else:
                out.append(byte)
                break
    return base64.b64encode(bytes(out)).decode()


def extract_mid(url: str) -> str:
    """从公众号文章 URL 提取 mid（稳定唯一 ID）。

    评论接口与微信读书侧标题经常不一致（如 "XCPDF V7.0" vs "XCPDF V6.5"），
    不能用标题匹配，改用 content_url 里的 mid 精确匹配。
    """
    try:
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(url or "").query)
        return (qs.get("mid") or [""])[0]
    except Exception:
        return ""


def extract_mid_from_html(html: str) -> str:
    """从公众号文章正文 HTML 提取 mid。

    注意：文章页的 og:url 是短链（https://mp.weixin.qq.com/s/xxx），不含 mid；
    真实 mid 在 HTML 的 JS 变量里，形如 `mid: "2648353022" || ""`。
    评论侧 content_url 才带 mid（?__biz=..&mid=..&idx=..），两者靠 mid 对齐。
    """
    try:
        m = re.search(r'mid\s*:\s*["\'](\d+)["\']', html or "")
        if m:
            return m.group(1)
        m = re.search(r'var\s+mid\s*=\s*["\']?(\d+)', html or "")
        return m.group(1) if m else ""
    except Exception:
        return ""


def _bizuin_from_cookie(cookie: str) -> str:
    """从后台 Cookie 提取 bizuin（公众号唯一 ID），用于评论映射缓存的命名空间。"""
    m = re.search(r'(?:^|;\s*)(?:bizuin|data_bizuin|slave_bizuin)=(\d+)', cookie or "")
    return m.group(1) if m else ""


def _load_comment_map(bizuin: str) -> dict:
    """加载本地缓存：mid -> comment_id（按 bizuin 分组）。"""
    try:
        data = json.loads(COMMENT_MAP_CACHE.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            return dict(data.get(str(bizuin), {}) or {})
    except Exception:
        pass
    return {}


def _save_comment_map(bizuin: str, mapping: dict):
    """增量写回本地缓存：mid -> comment_id。"""
    if not bizuin or not mapping:
        return
    try:
        data = {}
        try:
            data = json.loads(COMMENT_MAP_CACHE.read_text(encoding="utf-8"))
        except Exception:
            data = {}
        if not isinstance(data, dict):
            data = {}
        merged = dict(data.get(str(bizuin), {}) or {})
        merged.update({str(k): str(v) for k, v in mapping.items() if k and v})
        data[str(bizuin)] = merged
        COMMENT_MAP_CACHE.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception:
        pass


def fetch_comment_articles(cred: dict) -> list:
    """获取所有有评论的文章（comment_id + 评论数），带 buffer 分页。

    get_unread_appmsg_comment 需要 timestamp（当前秒级时间戳）与 buffer
    （protobuf 编码的「已加载 comment_id 列表」，第一页为空）两个参数，
    缺一不可（否则返回 ret=200002 invalid args）。
    """
    items = []
    seen = set()
    buffer = ""
    # count 上限实测为 50（60 会报 ret=200002）。用 50 一次拉全，避免 buffer 翻页
    # （buffer 翻页会返回重复数据，实际拿不到第 11 篇以后的文章，导致只拉到 10 篇）。
    count = 50
    while True:
        params = {
            "action": "get_unread_appmsg_comment",
            "begin": "0", "count": str(count), "sort_type": "0",
            "sendtype": "MASSSEND",
            "timestamp": str(int(time.time())),
            "buffer": buffer,
            "fingerprint": cred.get("fingerprint", ""),
            "token": cred.get("token", ""),
        }
        data = _mp_comment_get(cred.get("cookie", ""), params)
        br = data.get("base_resp", {}) or {}
        if br.get("ret", 0) != 0:
            raise RuntimeError(f"评论列表接口返回错误 ret={br.get('ret')}：{br.get('err_msg')}（token/fingerprint/Cookie 可能失效）")
        batch = data.get("item", []) or []
        if not batch:
            break
        added = 0
        for it in batch:
            cid = str(it.get("comment_id", "") or "")
            if cid and cid not in seen:
                seen.add(cid)
                items.append(it)
                added += 1
        if added == 0 or len(batch) < count:
            break
        # 下一页：把已加载的 comment_id 列表作为 buffer 继续
        buffer = _build_comment_buffer([str(it.get("comment_id", "") or "") for it in items])
        time.sleep(0.3)
    return items


def fetch_article_comments(cred: dict, comment_id: str) -> dict:
    """获取某篇文章的全部评论（含标题、content_url）。"""
    all_comments = []
    meta = {}
    begin = 0
    total = 0
    while True:
        params = {
            "action": "list_comment",
            "count": "20", "begin": str(begin),
            "comment_id": comment_id,
            "filtertype": "0", "day": "0", "type": "2", "max_id": "0",
            "fingerprint": cred.get("fingerprint", ""),
            "token": cred.get("token", ""),
        }
        data = _mp_comment_get(cred.get("cookie", ""), params)
        br = data.get("base_resp", {}) or {}
        if br.get("ret", 0) != 0:
            raise RuntimeError(f"评论详情接口返回错误 ret={br.get('ret')}：{br.get('err_msg')}")

        raw = data.get("comment_list", "")
        if not raw:
            break
        # comment_list 是 JSON 字符串（非 base64）
        try:
            cl = json.loads(raw)
        except Exception:
            cl = {}
        if not meta:
            content_url = data.get("content_url") or ""
            meta = {
                "title": data.get("title") or cl.get("title", ""),
                "content_url": content_url,
                "mid": extract_mid(content_url),
                "comment_id": comment_id,
            }
        total = cl.get("total_count") or 0
        comments = cl.get("comment", []) or []
        for c in comments:
            replies = []
            reply_obj = c.get("reply", {}) or {}
            for r in reply_obj.get("reply_list", []) or []:
                replies.append({
                    "nick": r.get("nick_name") or "",
                    "content": r.get("content") or "",
                    "time": r.get("create_time") or 0,
                    "like": r.get("reply_like_num") or 0,
                    "from_author": bool(r.get("reply_from_author")),
                })
            all_comments.append({
                "nick": c.get("nick_name") or "",
                "content": c.get("content") or "",
                "time": c.get("post_time") or 0,
                "like": c.get("like_num") or 0,
                "elected": bool(c.get("is_elected")),
                "replies": replies,
            })
        begin += len(comments)
        if not comments or (total and len(all_comments) >= total):
            break
        time.sleep(0.3)

    meta["total_count"] = total
    meta["comments"] = all_comments
    return meta


# ---------------------------------------------------------------------------
# Markdown 生成
# ---------------------------------------------------------------------------

def article_to_markdown(article: dict, comments: dict | None) -> str:
    parts = []
    title = article.get("title", "")
    parts.append(f"# {title}\n")
    meta_lines = []
    if article.get("time"):
        try:
            meta_lines.append(f"发布时间：{datetime.fromtimestamp(int(article['time'])).strftime('%Y-%m-%d %H:%M')}")
        except Exception:
            pass
    if article.get("read_num") or article.get("like_num"):
        meta_lines.append(f"阅读 {article.get('read_num', 0)} · 点赞 {article.get('like_num', 0)}")
    if article.get("content_url"):
        meta_lines.append(f"原文链接：{article['content_url']}")
    if meta_lines:
        parts.append("> " + "  \n> ".join(meta_lines) + "\n")
    parts.append("---\n\n")
    parts.append(article.get("body_md", "") + "\n")

    if comments and comments.get("comments"):
        parts.append("\n---\n\n## 评论（%d 条）\n" % len(comments["comments"]))
        for i, c in enumerate(comments["comments"], 1):
            t = ""
            if c.get("time"):
                try:
                    t = datetime.fromtimestamp(int(c["time"])).strftime('%Y-%m-%d %H:%M')
                except Exception:
                    t = ""
            like = f" · 赞{c['like']}" if c.get("like") else ""
            mark = " ⭐精选" if c.get("elected") else ""
            parts.append(f"**{i}. {c['nick']}**" + (f" _({t})_" if t else "") + f"{like}{mark}\n\n")
            parts.append(f"{c['content']}\n\n")
            for r in c.get("replies", []):
                who = r.get("nick") or "作者"
                parts.append(f"> **{who}（回复）**：{r['content']}\n")
            parts.append("\n")
    return "".join(parts)


# ---------------------------------------------------------------------------
# HTML / TXT / PDF 导出
# ---------------------------------------------------------------------------

def comments_to_html(comments: dict | None) -> str:
    """把评论渲染为 HTML 片段，追加到正文之后。"""
    if not comments or not comments.get("comments"):
        return ""
    items = comments["comments"]
    parts = [f'<hr style="margin:28px 0;border:none;border-top:1px solid #e3e6ea;">',
             f'<h2 style="margin:0 0 16px;">评论（{len(items)} 条）</h2>']
    for i, c in enumerate(items, 1):
        t = ""
        if c.get("time"):
            try:
                t = datetime.fromtimestamp(int(c["time"])).strftime("%Y-%m-%d %H:%M")
            except Exception:
                t = ""
        like = f' <span style="color:#8a919c;">· 赞{c["like"]}</span>' if c.get("like") else ""
        mark = ' <span style="color:#18a058;">⭐精选</span>' if c.get("elected") else ""
        parts.append(
            '<div style="margin:0 0 18px;padding:12px 14px;background:#fafbfc;border-radius:8px;">'
            f'<p style="margin:0 0 6px;"><strong>{i}. {escape(c["nick"])}</strong>'
            + (f' <span style="color:#8a919c;font-size:12px;">({escape(t)})</span>' if t else "")
            + f'{like}{mark}</p>'
            f'<p style="margin:0;">{escape(c["content"])}</p>'
        )
        for r in c.get("replies", []):
            who = r.get("nick") or "作者"
            parts.append(
                '<p style="margin:6px 0 0 12px;padding-left:8px;border-left:2px solid #c8d6ff;'
                f'color:#2f6bff;">{escape(who)}（回复）：{escape(r["content"])}</p>'
            )
        parts.append("</div>")
    return "\n".join(parts)


def comments_to_text(comments: dict | None) -> str:
    """把评论渲染为纯文本，追加到正文之后。"""
    if not comments or not comments.get("comments"):
        return ""
    items = comments["comments"]
    lines = ["", "=" * 40, f"评论（{len(items)} 条）", "=" * 40]
    for i, c in enumerate(items, 1):
        t = ""
        if c.get("time"):
            try:
                t = datetime.fromtimestamp(int(c["time"])).strftime("%Y-%m-%d %H:%M")
            except Exception:
                t = ""
        like = f" · 赞{c['like']}" if c.get("like") else ""
        mark = " ⭐精选" if c.get("elected") else ""
        head = f"{i}. {c['nick']}" + (f" ({t})" if t else "") + like + mark
        lines.append(head)
        lines.append(c["content"])
        for r in c.get("replies", []):
            who = r.get("nick") or "作者"
            lines.append(f"    └ {who}（回复）：{r['content']}")
        lines.append("")
    return "\n".join(lines)


def html_to_text(content_html: str) -> str:
    """从正文 HTML 提取纯文本（剥离脚本/样式/标签，保留段落换行）。"""
    html = re.sub(r'<script\b[^>]*>([\s\S]*?)</script>', '', content_html, flags=re.I)
    html = re.sub(r'<style\b[^>]*>([\s\S]*?)</style>', '', html, flags=re.I)
    html = re.sub(r'<(p|br|div|h1|h2|h3|h4|h5|h6|li|tr|section|blockquote)[^>]*>', '\n', html)
    text = re.sub(r'<[^>]+>', '', html)
    text = unescape(text)
    lines = []
    for line in text.split('\n'):
        s = line.strip()
        if s:
            lines.append(s)
        elif not lines or lines[-1] != "":
            lines.append("")
    return '\n'.join(lines).strip()


def build_full_html(article: dict, content_html: str, comments: dict | None) -> str:
    """把正文 HTML + 评论包装成完整、适合打印/PDF 的 HTML 文档。"""
    title = article.get("title", "")
    meta_lines = []
    if article.get("time"):
        try:
            meta_lines.append(f"发布时间：{datetime.fromtimestamp(int(article['time'])).strftime('%Y-%m-%d %H:%M')}")
        except Exception:
            pass
    if article.get("read_num") or article.get("like_num"):
        meta_lines.append(f"阅读 {article.get('read_num', 0)} · 点赞 {article.get('like_num', 0)}")
    if article.get("content_url"):
        meta_lines.append(f'原文链接：<a href="{escape(article["content_url"])}">{escape(article["content_url"])}</a>')
    meta_html = ""
    if meta_lines:
        meta_html = '<div class="meta">' + "".join(f"<p>{m}</p>" for m in meta_lines) + "</div>"
    body = content_html + comments_to_html(comments)
    return (
        '<!DOCTYPE html>\n<html lang="zh-CN">\n<head>\n'
        '  <meta charset="UTF-8">\n'
        '  <meta name="viewport" content="width=device-width, initial-scale=1.0">\n'
        f'  <title>{escape(title)}</title>\n'
        '  <style>\n'
        '    @page { margin: 16mm 14mm; size: A4; }\n'
        "    body { max-width: 760px; margin: 0 auto; padding: 24px; font-family: -apple-system, 'PingFang SC', 'Microsoft YaHei', 'Noto Sans CJK SC', sans-serif;\n"
        '           line-height: 1.8; color: #333; word-break: break-word; }\n'
        '    h1 { font-size: 24px; margin: 0 0 8px; line-height: 1.4; }\n'
        '    .meta { color: #8a919c; font-size: 13px; border-bottom: 1px solid #e3e6ea; padding-bottom: 12px; margin-bottom: 20px; }\n'
        '    .meta p { margin: 4px 0; }\n'
        '    img, video { max-width: 100%; height: auto; display: block; margin: 14px auto; page-break-inside: avoid; break-inside: avoid; border-radius: 4px; }\n'
        '    h1, h2, h3, h4, h5, h6 { page-break-after: avoid; break-after: avoid; color: #111; }\n'
        '    blockquote { margin: 14px 0; padding: 10px 16px; background: #f8f9fa; border-left: 4px solid #07c160; color: #555; }\n'
        '    table { width: 100%; border-collapse: collapse; margin: 15px 0; }\n'
        '    th, td { border: 1px solid #ddd; padding: 8px 12px; text-align: left; }\n'
        '    th { background-color: #f2f2f2; font-weight: 600; }\n'
        '    code, pre { font-family: Consolas, Menlo, monospace; background-color: #f6f8fa; border-radius: 4px; }\n'
        '    pre { padding: 12px; overflow-x: auto; line-height: 1.5; }\n'
        '  </style>\n</head>\n<body>\n'
        f'<h1>{escape(title)}</h1>\n'
        f'{meta_html}\n'
        '<div class="content">\n' + body + '\n</div>\n'
        '</body>\n</html>'
    )


def find_chromium_executable() -> str | None:
    """查找系统中可用的 Chrome / Edge / Chromium 可执行文件路径。"""
    custom = os.environ.get("CHROME_PATH") or os.environ.get("CHROMIUM_PATH")
    if custom and Path(custom).exists():
        return custom
    candidates = []
    for base in (os.environ.get("PROGRAMFILES"), os.environ.get("PROGRAMFILES(X86)"),
                 os.environ.get("LOCALAPPDATA")):
        if base:
            candidates.append(str(Path(base) / "Google" / "Chrome" / "Application" / "chrome.exe"))
            candidates.append(str(Path(base) / "Microsoft" / "Edge" / "Application" / "msedge.exe"))
    candidates.append(str(Path(os.environ.get("WINDIR", r"C:\Windows")) / "SystemApps"
                         / "Microsoft.MicrosoftEdge_8wekyb3d8bbwe" / "msedge.exe"))
    for p in candidates:
        try:
            if p and Path(p).exists():
                return p
        except Exception:
            continue
    return None


def export_html_to_pdf(html_path: Path, pdf_path: Path) -> bool:
    """用系统 Chrome/Edge 的 headless 模式将 HTML 转成 PDF（无需额外依赖）。"""
    chrome = find_chromium_executable()
    if not chrome:
        return False
    try:
        pdf_path.parent.mkdir(parents=True, exist_ok=True)
        cmd = [chrome, "--headless", "--disable-gpu", "--no-pdf-header-footer",
               f"--print-to-pdf={str(pdf_path.resolve())}", str(html_path.resolve())]
        subprocess.run(cmd, capture_output=True, timeout=90)
        return pdf_path.exists() and pdf_path.stat().st_size > 0
    except Exception:
        return False


def _export_one(art: dict, out_dir: Path, formats: set, comments_by_mid: dict,
                layout: str, download_images: bool, cookie: str):
    """导出单篇文章，返回 (success, comment_count, logs)。

    每篇独立目录（subdir）或独立文件名（flat），图片目录按文章名区分。
    """
    logs = []
    raw_html = ""
    content_html = ""
    source = ""
    notes = []  # 各通路的失败原因，最终汇总进报错文案，便于定位

    if art.get("_raw_html"):
        raw_html = art["_raw_html"]
        source = "预抓取缓存"
        content_html = extract_content_html(raw_html)

    # 通路1：微信读书正文（登录态，风控宽松，批量优先）
    if not content_html and art.get("review_id") and cookie:
        try:
            raw_html = fetch_article_html(cookie, art["review_id"])
            content_html = extract_content_html(raw_html)
            source = "微信读书"
            if not content_html:
                notes.append(f"微信读书：{_diagnose_article_html(raw_html)}")
        except Exception as e:
            notes.append(f"微信读书：{_brief_err(e)}")

    # 顺手从已拿到的页面里取短链（og:url）：既作原文链接，也作直访回退入口
    if raw_html:
        og = extract_meta(raw_html, "og:url") or ""
        if og.startswith("http"):
            if not art.get("url"):
                art["url"] = og
            if not art.get("content_url"):
                art["content_url"] = og

    # 通路2：短链直访（免登录，模式3 已验证纯短链稳定）
    if not content_html and art.get("url"):
        try:
            raw2 = fetch_article_html_direct(art["url"])
            c2 = extract_content_html(raw2)
            if c2:
                raw_html, content_html = raw2, c2
                source = "短链直访（回退）"
                logs.append("微信读书无正文，已改用短链直访成功")
            else:
                notes.append(f"短链直访：{_diagnose_article_html(raw2)}")
        except Exception as e:
            notes.append(f"短链直访：{_brief_err(e)}")

    if not content_html:
        detail = "；".join(notes) if notes else "无可用链接或 review_id"
        raise RuntimeError(f"未提取到正文（{detail}）")

    art["content_url"] = (extract_meta(raw_html, "og:url") or art.get("url")
                          or art.get("content_url") or "")

    safe = sanitize(art["title"])
    date = art.get("create_time") or ""
    if not date and art.get("time"):
        try:
            date = datetime.fromtimestamp(int(art["time"])).strftime("%Y-%m-%d")
        except Exception:
            date = ""
    fname = f"{date}_{safe}" if date else safe

    if layout == "flat":
        # 平铺：所有文件直接放 out_dir，图片放「文章文件名_files」子目录
        article_dir = out_dir
        media_dir = out_dir / f"{fname}_files"
        rel_prefix = f"{fname}_files"
    else:
        # 每篇一个子文件夹，图片放 images/ 子目录
        article_dir = out_dir / fname
        media_dir = article_dir / "images"
        rel_prefix = "images"
    article_dir.mkdir(parents=True, exist_ok=True)

    img_count = 0
    if download_images:
        content_html, img_count = localize_images(content_html, media_dir, rel_prefix)
        if img_count:
            logs.append(f"已下载 {img_count} 张图片")
    art["body_md"] = html_to_markdown(content_html)

    # 匹配评论：优先按 mid（正文 HTML 里的稳定 ID）精确匹配
    art_mid = extract_mid_from_html(raw_html) or extract_mid(art.get("content_url", ""))
    comments = comments_by_mid.get(art_mid) if art_mid else None
    if comments is None and comments_by_mid:
        # 兜底：mid 缺失时按标题模糊匹配
        for cm in comments_by_mid.values():
            t = cm.get("title", "")
            if t and (t in art["title"] or art["title"] in t):
                comments = cm
                break

    if "markdown" in formats:
        (article_dir / f"{fname}.md").write_text(article_to_markdown(art, comments), encoding="utf-8")
    html_path = None
    if "html" in formats or "pdf" in formats:
        html_path = article_dir / f"{fname}.html"
        html_path.write_text(build_full_html(art, content_html, comments), encoding="utf-8")
    if "txt" in formats:
        txt = f"# {art['title']}\n\n" + html_to_text(content_html) + comments_to_text(comments)
        (article_dir / f"{fname}.txt").write_text(txt, encoding="utf-8")
    if "pdf" in formats and html_path:
        if not export_html_to_pdf(html_path, article_dir / f"{fname}.pdf"):
            logs.append("PDF 转换失败（未检测到 Chrome/Edge）")
    comment_count = len(comments.get("comments", [])) if comments else 0
    return True, comment_count, logs


# ---------------------------------------------------------------------------
# 导出任务（后台线程）
# ---------------------------------------------------------------------------

def export_worker(task_id: str):
    task = TASKS[task_id]
    cfg = task["cfg"]
    try:
        # 预置变量，确保中途停止/异常时也能安全引用
        articles = []
        ok = 0
        total_comments = 0
        results = []
        out_dir = None
        formats = set()
        cookie = cfg.get("weread_cookie", "")
        keyword = cfg.get("keyword", "")
        token = cfg.get("token", "")
        mp_cookie = cfg.get("mp_cookie", "")
        selected = cfg.get("articles") or None  # 前端勾选的文章列表（选择性下载）
        # 数据源：填了后台 token + Cookie 则优先用公众号后台「原创」列表，否则回退微信读书
        use_mp_source = bool(token and mp_cookie)
        if selected:
            # 选中模式：直接使用前端传入的文章列表，不再重新拉取
            articles = selected
            # 名称兜底：前端未带时用本次会话缓存的公众号名/bookId，避免文件夹退化成「article」
            book_id = cfg.get("book_id") or CACHE.get("book_id") or ""
            mp_name = cfg.get("mp_name") or CACHE.get("mp_name") or ""
            CACHE["book_id"] = book_id
            CACHE["mp_name"] = mp_name
            task_log(task, f"使用选中的 {len(articles)} 篇文章")
        else:
            if use_mp_source:
                task_log(task, "使用公众号后台「原创」列表拉取文章 ...")
                articles, mp_name = fetch_all_articles_from_mp(
                    mp_cookie, token, task=task,
                    max_articles=int(cfg.get("max_articles", 0) or 0))
                book_id = ""
                CACHE["book_id"] = book_id
                CACHE["mp_name"] = mp_name
                if not articles:
                    raise RuntimeError("后台「原创」列表未获取到任何文章，请检查 token 与后台 Cookie")
                task_log(task, f"共 {len(articles)} 篇（原创）")
            else:
                task_log(task, "解析公众号 bookId ...")
                book_id, mp_name = resolve_book_id(cookie, keyword)
                CACHE["book_id"] = book_id
                CACHE["mp_name"] = mp_name
                task_log(task, f"  bookId = {book_id}  {('（' + mp_name + '）') if mp_name else ''}")

                task_log(task, "拉取全部文章列表 ...")
                articles, got_name = fetch_all_articles(cookie, book_id, task=task,
                                                        max_articles=int(cfg.get("max_articles", 0) or 0))
                if not mp_name and got_name:
                    mp_name = got_name
                    CACHE["mp_name"] = mp_name
                if not articles:
                    raise RuntimeError("未获取到任何文章，请检查 bookId 与 Cookie")
                task_log(task, f"共 {len(articles)} 篇文章")

        # 评论凭证
        cred = {}
        if cfg.get("fetch_comments"):
            cred = {
                "token": cfg.get("token", ""),
                "fingerprint": cfg.get("fingerprint", ""),
                "cookie": cfg.get("mp_cookie", ""),
            }
            if not (cred.get("token") and cred.get("fingerprint")):
                task_log(task, "未填写 token/fingerprint，跳过评论")
                cred = {}

        # 选中模式：先预抓选中文章正文，提取 mid（用于评论定位）
        # 仅当需要拉评论（有后台凭证）时才预抓取；无评论时正文在串行导出阶段拉取
        selected_mids = set()
        selected_had_mids = False
        if selected and cred:
            task_log(task, f"预抓取 {len(articles)} 篇正文以定位评论 ...")
            for art in articles:
                try:
                    raw_html = (fetch_article_html_direct(art["url"]) if art.get("url")
                                else (fetch_article_html(cookie, art["review_id"]) if art.get("review_id") else ""))
                    art["_raw_html"] = raw_html  # 缓存，导出时复用，避免重复抓取
                    art["content_url"] = extract_meta(raw_html, "og:url") or ""
                    m = extract_mid_from_html(raw_html)
                    if m:
                        selected_mids.add(m)
                except Exception:
                    pass
            selected_had_mids = bool(selected_mids)
            if selected_mids:
                task_log(task, f"  已获取 {len(selected_mids)} 个 mid")

        # 评论拉取（若有凭证），用 mid 建索引；配合本地缓存 mid->comment_id 避免重复遍历
        comments_by_mid = {}
        if cred.get("token") and cred.get("fingerprint"):
            bizuin = _bizuin_from_cookie(cred.get("cookie", "")) or \
                     (book_id.replace("MP_WXS_", "") if book_id else "")
            cache_map = _load_comment_map(bizuin)
            new_map = {}  # 本次新建的 mid->comment_id，稍后回写缓存

            # 1) 缓存命中：选中文章的 mid 已有 comment_id，直接拉详情，无需遍历
            if selected and selected_mids and cache_map:
                hit = sum(1 for m in selected_mids if m in cache_map)
                if hit:
                    task_log(task, f"  评论映射缓存命中 {hit}/{len(selected_mids)} 篇，直接拉取 ...")
                for mid in list(selected_mids):
                    cid = cache_map.get(mid)
                    if not cid:
                        continue
                    try:
                        meta = fetch_article_comments(cred, cid)
                        comments_by_mid[mid] = meta
                        selected_mids.discard(mid)
                        task_log(task, f"  [缓存] {meta.get('title','')[:30]}：{len(meta.get('comments',[]))} 条评论")
                    except Exception as e:
                        task_log(task, f"  [缓存失败] comment_id={cid}：{e}")
                    time.sleep(0.3)

            # 2) 遍历 comment_id 列表：
            #    非选中模式总是遍历（需要全部评论内容）；选中模式在「还有未命中 mid」或「预抓没拿到 mid」时遍历（兜底）
            if (not selected) or selected_mids or (selected and not selected_had_mids):
                comment_articles = fetch_comment_articles(cred)
                task_log(task, f"拉取每篇文章的评论（共 {len(comment_articles)} 篇有评论）...")
                matched_mids = set()
                cached_cids = set(cache_map.values())  # 已缓存的 comment_id：其 mid 不在 selected_mids，选中模式可直接跳过
                for i, ca in enumerate(comment_articles, 1):
                    cid = str(ca.get("comment_id", "") or "")
                    # 选中模式：已缓存的无关 comment_id 无需再 list_comment（节省请求，降低封号风险）
                    if selected and cid in cached_cids:
                        continue
                    try:
                        meta = fetch_article_comments(cred, cid)
                        mid = meta.get("mid", "")
                        if mid:
                            comments_by_mid[mid] = meta
                            new_map[mid] = cid  # 记录映射，回写缓存
                            if mid in selected_mids:
                                matched_mids.add(mid)
                        task_log(task, f"  [{i}/{len(comment_articles)}] {meta.get('title','')[:30]}：{len(meta.get('comments',[]))} 条评论")
                    except Exception as e:
                        task_log(task, f"  [失败] comment_id={cid}：{e}")
                    # 选中模式：所有选中文章都已匹配到评论，提前停止
                    if selected and selected_mids and matched_mids >= selected_mids:
                        task_log(task, "  已匹配到所有选中文章的评论，提前停止")
                        break
                    time.sleep(0.5)

            # 3) 回写缓存（新增的 mid->comment_id 映射）
            if new_map:
                _save_comment_map(bizuin, new_map)

        # 输出目录（文件夹名带导出日期，如 相声的技术备忘录_2026-10-19）
        export_date = datetime.now().strftime("%Y-%m-%d")
        # 文件夹名优先用公众号名，其次 bookId，最后兜底「未命名公众号」（不再退化成 article）
        base_dir_name = sanitize(mp_name or book_id or "未命名公众号")
        out_dir = Path(cfg.get("output_dir") or OUTPUT_ROOT) / f"{base_dir_name}_{export_date}"
        out_dir.mkdir(parents=True, exist_ok=True)

        # 导出格式（默认仅 markdown，保持向后兼容）
        formats = set()
        for f in (cfg.get("export_formats") or ["markdown"]):
            f = str(f).lower().strip()
            if f in ("md", "markdown"):
                formats.add("markdown")
            elif f in ("html", "htm"):
                formats.add("html")
            elif f == "txt":
                formats.add("txt")
            elif f == "pdf":
                formats.add("pdf")
        if not formats:
            formats = {"markdown"}
        task_log(task, f"导出格式：{', '.join(sorted(formats))}")

        # 导出选项：布局（每篇子文件夹 / 平铺）+ 是否下载图片（串行导出，防风控）
        layout = str(cfg.get("layout") or "subdir")
        download_images = bool(cfg.get("download_images", True))
        task_log(task, f"布局：{'平铺到同一目录' if layout == 'flat' else '每篇一个子文件夹'}，"
                       f"图片：{'下载' if download_images else '不下载'}，串行下载（防风控）")

        # 逐篇串行导出：慢但稳定，避免并发请求触发微信风控
        ok = 0
        total_comments = 0
        total = len(articles)
        results = []  # 每篇结果：{uid, title, success, error}，供前端移除成功项/保留失败项

        for n, art in enumerate(articles, 1):
            _check_stop(task)  # 用户点「停止下载」后在此退出
            err_msg = ""
            try:
                success, cc, logs = _export_one(art, out_dir, formats, comments_by_mid,
                                                layout, download_images, cookie)
            except Exception as e:
                success, cc, logs = False, 0, []
                err_msg = str(e)
                task_log(task, f"  [失败] {art['title'][:40]}：{e}")
            if success:
                ok += 1
                total_comments += cc
            for lg in logs:
                task_log(task, f"  {art['title'][:40]}：{lg}")
            if success:
                task_log(task, f"[{n}/{total}] {art['title'][:40]}")
            results.append({"uid": art.get("uid"), "title": art.get("title", ""),
                            "success": success, "error": err_msg})
            # 实时进度：每完成一篇就暴露给前端，列表可即时移除成功项/标红失败项
            task["results_sofar"] = list(results)
            # 串行限速：篇与篇之间暂停，降低风控概率
            time.sleep(1.2)

        task["result"] = {"ok": ok, "total": len(articles), "comments": total_comments,
                          "formats": sorted(formats), "dir": str(out_dir), "results": results}
        task["status"] = "done"
        task_log(task, f"完成：成功 {ok}/{len(articles)} 篇，共 {total_comments} 条评论，格式 {', '.join(sorted(formats))}")
        task_log(task, f"输出目录：{out_dir}")
    except TaskStopped:
        task["status"] = "stopped"
        task["result"] = {"ok": ok, "total": len(articles), "comments": total_comments,
                          "formats": sorted(formats),
                          "dir": str(out_dir) if out_dir else "",
                          "results": results, "stopped": True}
        task_log(task, "已停止下载（剩余文章保留在列表，可再次点击下载继续）")
    except Exception as e:
        task["status"] = "error"
        task["error"] = str(e)
        task_log(task, f"任务失败：{e}")


# ---------------------------------------------------------------------------
# 读者模式：mitmproxy 采集微信登录态凭证 + 抓取精选评论
# ---------------------------------------------------------------------------

def _win_proxy(enable: bool, proxy: str = "") -> None:
    """设置 / 清除 Windows 系统代理（WinINET，当前用户，无需管理员）。"""
    try:
        import winreg
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                             r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
                             0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1 if enable else 0)
        if proxy:
            winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, proxy)
        # 本机服务不走代理，避免杀掉 mitmproxy 时切断页面与后端的通信
        winreg.SetValueEx(key, "ProxyOverride", 0, winreg.REG_SZ,
                          "127.0.0.1;localhost;<local>")
        winreg.CloseKey(key)
    except Exception:
        pass
    # 通知系统刷新代理设置，让已运行的进程尽快感知
    try:
        import ctypes
        ctypes.windll.wininet.InternetSetOptionW(0, 39, 0, 0)
        ctypes.windll.wininet.InternetSetOptionW(0, 37, 0, 0)
    except Exception:
        pass


def _wechat_proc_info() -> dict:
    """检测微信进程状态：Weixin.exe 主进程启动时间 + WeChatAppEx.exe 文章窗口数。"""
    try:
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
        r = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "Get-Process Weixin,WeChatAppEx -ErrorAction SilentlyContinue | "
             "ForEach-Object { try { '{0}|{1:yyyy-MM-dd HH:mm:ss}' -f $_.Name, $_.StartTime } catch {} }"],
            capture_output=True, text=True, timeout=10, creationflags=creationflags)
        main_start = ""
        ex_count = 0
        for line in (r.stdout or "").splitlines():
            line = line.strip()
            if not line or "|" not in line:
                continue
            name, _, st = line.partition("|")
            if name.lower() == "weixin":
                if not main_start or st < main_start:
                    main_start = st
            elif name.lower() == "wechatappex":
                ex_count += 1
        return {"main_start": main_start, "ex_count": ex_count}
    except Exception:
        return {"main_start": "", "ex_count": 0}


def _install_mitm_cert() -> bool:
    """安装 mitmproxy CA 到「当前用户」根证书库（无需管理员）。"""
    if not MITM_CA_CER.exists():
        return False
    try:
        r = subprocess.run(["certutil", "-user", "-addstore", "root", str(MITM_CA_CER)],
                           capture_output=True, timeout=30)
        return r.returncode == 0
    except Exception:
        return False


def _start_mitmdump():
    """启动 mitmdump 子进程，返回 (proc, err)。"""
    if not MITMDUMP.exists():
        return None, f"未找到 mitmdump（{MITMDUMP}）。请先在 .mitmvenv 里安装 mitmproxy。"
    try:
        out = open(MITM_LOG, "a", encoding="utf-8")
        err = open(MITM_ERR, "a", encoding="utf-8")
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
        proc = subprocess.Popen(
            [str(MITMDUMP), "-p", str(MITM_PROXY_PORT), "-s", "mitm_cred.py"],
            cwd=str(SCRIPT_DIR), stdout=out, stderr=err, creationflags=creationflags)
        return proc, None
    except Exception as e:
        return None, str(e)


def _kill_mitmdump():
    """强制结束所有 mitmdump.exe 进程，确保下次启动加载最新插件代码。"""
    if os.name != "nt":
        return
    try:
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        subprocess.run(["taskkill", "/F", "/IM", "mitmdump.exe"],
                       capture_output=True, timeout=15, creationflags=creationflags)
    except Exception:
        pass


def start_reader_capture():
    """启动凭证采集：装证书 + 起 mitmdump + 设系统代理。"""
    global MITM_STATE
    with MITM_LOCK:
        if MITM_STATE["running"]:
            return False, "采集已在运行中"
        # 只保留本次采集的记录：清空上一轮的凭证与文章列表
        try:
            READER_CRED_FILE.write_text("[]", encoding="utf-8")
            READER_ARTICLE_FILE.write_text("[]", encoding="utf-8")
        except Exception:
            pass
        # 清理残留的 mitmdump（端口占用会导致新插件不生效）
        _kill_mitmdump()
        time.sleep(0.5)
        MITM_STATE["wechat_start0"] = _wechat_proc_info().get("main_start", "")
        cert_ok = _install_mitm_cert()
        proc, err = _start_mitmdump()
        if proc is None:
            return False, err
        time.sleep(1.0)
        _win_proxy(True, f"127.0.0.1:{MITM_PROXY_PORT}")
        MITM_STATE["running"] = True
        MITM_STATE["proc"] = proc
        MITM_STATE["message"] = ("证书已安装" if cert_ok else "⚠ 证书安装失败，可能无法解密 HTTPS")
        return True, "采集已启动：请完全退出并重开微信，然后打开要抓取的公众号文章"


def stop_reader_capture():
    """停止采集：恢复系统代理 + 结束 mitmdump。"""
    global MITM_STATE
    with MITM_LOCK:
        _win_proxy(False)
        proc = MITM_STATE.get("proc")
        if proc:
            try:
                proc.terminate()
            except Exception:
                pass
        _kill_mitmdump()
        MITM_STATE["running"] = False
        MITM_STATE["proc"] = None
        MITM_STATE["message"] = ""
        return True, "已停止采集，系统代理已恢复"


def _reader_capture_status() -> dict:
    creds = load_reader_credentials()
    arts = load_reader_articles()
    # 每个公众号统计本次打开的文章数
    art_count = {}
    for a in arts:
        if a.get("biz"):
            art_count[a["biz"]] = art_count.get(a["biz"], 0) + 1
    info = _wechat_proc_info() if MITM_STATE.get("running") else {"main_start": "", "ex_count": 0}
    main_start = info.get("main_start", "")
    start0 = MITM_STATE.get("wechat_start0", "")
    return {
        "running": bool(MITM_STATE.get("running")),
        "message": MITM_STATE.get("message", ""),
        "cred_count": len(creds),
        "credentials": [{"biz": b, "name": c.get("name", ""),
                         "article_count": art_count.get(b, 0)} for b, c in creds.items()],
        "article_count": len(arts),
        "articles": [{"biz": a.get("biz", ""), "title": a.get("title", ""),
                      "url": a.get("url", "")} for a in arts],
        "wechat_running": bool(main_start),
        "wechat_start": main_start,
        "wechat_restarted": bool(main_start) and main_start != start0,
    }


def load_reader_articles() -> list:
    """读取 articles.json：本次采集中打开的文章列表 [{biz,url,title,timestamp}]。"""
    if not READER_ARTICLE_FILE.exists():
        return []
    try:
        data = json.loads(READER_ARTICLE_FILE.read_text(encoding="utf-8"))
    except Exception:
        return []
    return data if isinstance(data, list) else []


def load_reader_credentials() -> dict:
    """读取 credentials.json，解析为 {biz: {uin,key,pass_ticket,appmsg_token,name}}。"""
    result = {}
    if not READER_CRED_FILE.exists():
        return result
    try:
        data = json.loads(READER_CRED_FILE.read_text(encoding="utf-8"))
    except Exception:
        return result
    if not isinstance(data, list):
        return result
    for item in data:
        if not isinstance(item, dict):
            continue
        biz = item.get("biz", "")
        if not biz:
            continue
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(item.get("url", "")).query)
        key = (qs.get("key") or [""])[0]
        uin = (qs.get("uin") or [""])[0]
        sc = item.get("set_cookie", "")

        def _gc(name):
            m = re.search(name + r'=([^;]+)', sc)
            return m.group(1) if m else ""

        result[biz] = {
            "biz": biz,
            "uin": uin,
            "key": key,
            "pass_ticket": _gc("pass_ticket"),
            "appmsg_token": _gc("appmsg_token"),
            "name": item.get("name", ""),
        }
    return result


def extract_idx_from_html(html: str) -> str:
    for pat in (r'var\s+idx\s*=\s*["\'](\d+)["\']',
                r'idx\s*:\s*["\']?(\d+)["\']?'):
        m = re.search(pat, html or "")
        if m and m.group(1):
            return m.group(1)
    return "1"


def extract_comment_id_from_html(html: str) -> str:
    for pat in (r'var\s+comment_id\s*=\s*["\'](\d+)["\']',
                r'comment_id\s*[:=]\s*["\']?(\d+)["\']?'):
        m = re.search(pat, html or "")
        if m and m.group(1):
            return m.group(1)
    return ""


def extract_publish_time(html: str) -> int:
    """从文章 HTML 提取发布时间（Unix 秒），提取不到返回 0。"""
    if not html:
        return 0
    # var ct = "176xxxxxxx"（Unix 秒）
    m = re.search(r'var\s+ct\s*=\s*["\']?(\d{10})["\']?', html)
    if m:
        try:
            return int(m.group(1))
        except Exception:
            pass
    # createTime / publish_time 等数字形式
    for name in ("createTime", "publish_time", "create_time", "CreateTime"):
        m = re.search(name + r'\s*[:=]\s*["\']?(\d{10})["\']?', html)
        if m:
            try:
                return int(m.group(1))
            except Exception:
                pass
    # 日期字符串 "2026-10-19"
    m = re.search(r'(20\d{2})[-/](\d{1,2})[-/](\d{1,2})', html)
    if m:
        try:
            return int(datetime(int(m.group(1)), int(m.group(2)), int(m.group(3))).timestamp())
        except Exception:
            pass
    return 0


def fetch_reader_article_comments(article_url: str, creds: dict) -> dict:
    """读者视角抓取单篇文章的精选评论（getcomment 接口）。

    返回结构与 fetch_article_comments 一致：{title, comments:[...], total_count, ...}。
    """
    try:
        import urllib3
        urllib3.disable_warnings()
    except Exception:
        pass
    raw_html = fetch_article_html_direct(article_url)
    if not extract_content_html(raw_html):
        raise RuntimeError("未提取到正文 #js_content（可能链接失效）")
    title = extract_meta(raw_html, "og:title") or ""
    biz = extract_biz_from_html(raw_html)
    mid = extract_mid_from_html(raw_html)
    idx = extract_idx_from_html(raw_html)
    comment_id = extract_comment_id_from_html(raw_html)

    if not (biz and mid and comment_id):
        return {"title": title, "comments": [], "total_count": 0, "note": "该文章未开启评论或无评论"}

    cred = creds.get(biz)
    if not cred or not cred.get("pass_ticket"):
        return {"title": title, "comments": [], "total_count": 0, "biz": biz,
                "note": "该公众号尚未采集凭证，请先到微信打开其一篇文章"}

    all_comments = []
    offset = 0
    total = 0
    while True:
        params = {
            "action": "getcomment", "scene": "0", "__biz": biz, "appmsgid": mid, "idx": idx,
            "comment_id": comment_id, "offset": str(offset), "limit": "100",
            "f": "json", "wxtoken": "777",
            "uin": cred.get("uin", ""), "key": cred.get("key", ""),
            "pass_ticket": cred.get("pass_ticket", ""),
        }
        resp = requests.get("https://mp.weixin.qq.com/mp/appmsg_comment", params=params,
                            headers={"User-Agent": UA, "Referer": "https://mp.weixin.qq.com/"},
                            timeout=30, verify=False)
        data = resp.json()
        br = data.get("base_resp", {}) or {}
        if br.get("ret", 0) != 0:
            raise RuntimeError(f"评论接口 ret={br.get('ret')}：{br.get('errmsg')}")
        total = data.get("elected_comment_total_cnt", 0) or 0
        batch = data.get("elected_comment", []) or []
        for c in batch:
            replies = []
            reply_obj = c.get("reply", {}) or {}
            for r in reply_obj.get("reply_list", []) or []:
                replies.append({
                    "nick": r.get("nick_name") or "",
                    "content": r.get("content") or "",
                    "time": r.get("create_time") or 0,
                    "like": r.get("reply_like_num") or 0,
                    "from_author": bool(r.get("reply_from_author")),
                })
            all_comments.append({
                "nick": c.get("nick_name") or "",
                "content": c.get("content") or "",
                "time": c.get("create_time") or 0,
                "like": c.get("like_num") or 0,
                "elected": True,
                "replies": replies,
            })
        if not batch or not data.get("continue_flag"):
            break
        offset += len(batch)
        time.sleep(0.3)

    return {"title": title, "comments": all_comments, "total_count": total, "biz": biz, "mid": mid}


def reader_export_worker(task_id: str):
    """读者模式导出：按粘贴的链接逐篇抓正文 + 精选评论，写多格式。"""
    task = TASKS[task_id]
    cfg = task["cfg"]
    try:
        # 预置变量，确保中途停止时也能安全引用
        urls = []
        ok = 0
        total_comments = 0
        results = []  # 每个链接结果：{url, title, success, error}
        out_dir = None
        formats = set()
        urls = [u.strip() for u in (cfg.get("article_urls") or []) if u and u.strip()]
        if not urls:
            raise RuntimeError("请先粘贴文章链接")
        creds = load_reader_credentials()

        formats = set()
        for f in (cfg.get("export_formats") or ["markdown"]):
            f = str(f).lower().strip()
            if f in ("md", "markdown"):
                formats.add("markdown")
            elif f in ("html", "htm"):
                formats.add("html")
            elif f == "txt":
                formats.add("txt")
            elif f == "pdf":
                formats.add("pdf")
        if not formats:
            formats = {"markdown"}

        layout = str(cfg.get("layout") or "subdir")
        download_images = bool(cfg.get("download_images", True))

        out_dir = Path(cfg.get("output_dir") or OUTPUT_ROOT) / f"读者导出_{datetime.now().strftime('%Y-%m-%d')}"
        out_dir.mkdir(parents=True, exist_ok=True)
        task_log(task, f"输出目录：{out_dir}")
        task_log(task, f"导出格式：{', '.join(sorted(formats))}，共 {len(urls)} 个链接")
        task_log(task, f"布局：{'平铺到同一目录' if layout == 'flat' else '每篇一个子文件夹'}，"
                       f"图片：{'下载' if download_images else '不下载'}")

        for i, url in enumerate(urls, 1):
            _check_stop(task)  # 用户点「停止下载」后在此退出
            title = f"文章{i}"
            err_msg = ""
            success = False
            try:
                raw_html = fetch_article_html_direct(url)
                content_html = extract_content_html(raw_html)
                if not content_html:
                    raise RuntimeError("未提取到正文")
                title = extract_meta(raw_html, "og:title") or f"文章{i}"
                safe = sanitize(title)
                date = ""
                m = re.search(r'var\s+ct\s*=\s*["\']?(\d{10})["\']?', raw_html or "")
                if m:
                    try:
                        date = datetime.fromtimestamp(int(m.group(1))).strftime("%Y-%m-%d")
                    except Exception:
                        date = ""
                fname = f"{date}_{safe}" if date else safe
                if layout == "flat":
                    # 平铺：文件直接放 out_dir，图片放「文章文件名_files」
                    article_dir = out_dir
                    media_dir = out_dir / f"{fname}_files"
                    rel_prefix = f"{fname}_files"
                else:
                    # 每篇一个子文件夹，图片放 images/
                    article_dir = out_dir / fname
                    media_dir = article_dir / "images"
                    rel_prefix = "images"
                article_dir.mkdir(parents=True, exist_ok=True)
                task_log(task, f"[{i}/{len(urls)}] {title[:40]}")
                if download_images:
                    content_html, img_count = localize_images(content_html, media_dir, rel_prefix)
                    if img_count:
                        task_log(task, f"    已下载 {img_count} 张图片")
                art = {"title": title, "body_md": html_to_markdown(content_html),
                       "content_url": url, "time": 0}
                comments = None
                if cfg.get("fetch_comments"):
                    try:
                        comments = fetch_reader_article_comments(url, creds)
                        if comments.get("comments"):
                            task_log(task, f"    已抓取 {len(comments['comments'])} 条精选评论")
                        elif comments.get("note"):
                            task_log(task, f"    {comments['note']}")
                    except Exception as e:
                        task_log(task, f"    [评论失败] {e}")
                if "markdown" in formats:
                    (article_dir / f"{fname}.md").write_text(article_to_markdown(art, comments), encoding="utf-8")
                if "html" in formats or "pdf" in formats:
                    full_html = build_full_html(art, content_html, comments)
                    html_path = article_dir / f"{fname}.html"
                    html_path.write_text(full_html, encoding="utf-8")
                else:
                    html_path = None
                if "txt" in formats:
                    txt = f"# {title}\n\n" + html_to_text(content_html) + comments_to_text(comments)
                    (article_dir / f"{fname}.txt").write_text(txt, encoding="utf-8")
                if "pdf" in formats and html_path:
                    pdf_path = article_dir / f"{fname}.pdf"
                    if not export_html_to_pdf(html_path, pdf_path):
                        task_log(task, f"  [警告] PDF 转换失败（未检测到 Chrome/Edge）")
                ok += 1
                success = True
                if comments:
                    total_comments += len(comments.get("comments", []))
            except Exception as e:
                err_msg = str(e)
                task_log(task, f"  [失败] {url[:60]}：{e}")
            results.append({"url": url, "title": title, "success": success, "error": err_msg})
            task["results_sofar"] = list(results)  # 实时进度
            time.sleep(1.2)

        task["result"] = {"ok": ok, "total": len(urls), "comments": total_comments,
                          "formats": sorted(formats), "dir": str(out_dir), "results": results}
        task["status"] = "done"
        task_log(task, f"完成：成功 {ok}/{len(urls)} 篇，共 {total_comments} 条评论")
    except TaskStopped:
        task["status"] = "stopped"
        task["result"] = {"ok": ok, "total": len(urls), "comments": total_comments,
                          "formats": sorted(formats),
                          "dir": str(out_dir) if out_dir else "",
                          "results": results, "stopped": True}
        task_log(task, "已停止下载（剩余链接保留在输入框，可再次点击下载继续）")
    except Exception as e:
        task["status"] = "error"
        task["error"] = str(e)
        task_log(task, f"任务失败：{e}")


# ---------------------------------------------------------------------------
# Flask 路由
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/weread_login", methods=["POST"])
def api_weread_login():
    try:
        return jsonify({"ok": True, **start_weread_login()})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})


@app.route("/api/weread_login_status")
def api_weread_login_status():
    return jsonify(_get_login("weread"))


@app.route("/api/mp_login", methods=["POST"])
def api_mp_login():
    try:
        return jsonify({"ok": True, **start_mp_login()})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})


@app.route("/api/mp_login_status")
def api_mp_login_status():
    return jsonify(_get_login("mp"))


@app.route("/api/config", methods=["GET", "POST"])
def api_config():
    global CONFIG
    if request.method == "POST":
        data = request.get_json(force=True) or {}
        for k in ("weread_cookie", "token", "fingerprint", "mp_cookie", "keyword", "mp_name",
                  "output_dir", "fetch_comments", "max_articles", "export_formats",
                  "layout", "download_images", "threads", "fetch_short_urls"):
            if k in data:
                CONFIG[k] = data[k]
        save_config()
        return jsonify({"ok": True, "config": CONFIG})
    return jsonify(CONFIG)


@app.route("/api/resolve", methods=["POST"])
def api_resolve():
    data = request.get_json(force=True) or {}
    cookie = data.get("weread_cookie", "")
    keyword = data.get("keyword", "")
    try:
        book_id, mp_name = resolve_book_id(cookie, keyword)
        CACHE["book_id"] = book_id
        CACHE["mp_name"] = mp_name
        return jsonify({"ok": True, "book_id": book_id, "mp_name": mp_name})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})


def fetch_articles_worker(tid):
    """拉取文章列表的后台任务：实时输出进度日志，完成后 result 带 articles/mp_name。"""
    task = TASKS[tid]
    data = task["cfg"]
    cookie = data.get("weread_cookie", "")
    keyword = data.get("keyword", "")
    token = data.get("token", "")
    mp_cookie = data.get("mp_cookie", "")
    max_articles = int(data.get("max_articles", 0) or 0)
    date_from = data.get("date_from", "")
    date_to = data.get("date_to", "")

    def _on_page(arts):
        # 每拉完一页，把当前累计文章暴露给前端增量渲染
        task["articles_sofar"] = list(arts)

    try:
        book_id = ""
        mp_name = ""
        if date_from or date_to:
            task_log(task, f"时间范围：{date_from or '不限'} ~ {date_to or '不限'}")
        if token and mp_cookie:
            # 优先后台「原创」列表
            task_log(task, "使用公众号后台「原创」列表拉取文章 ...")
            articles, mp_name = fetch_all_articles_from_mp(
                mp_cookie, token, task=task, max_articles=max_articles, on_page=_on_page,
                date_from=date_from, date_to=date_to)
            book_id = ""
            task_log(task, f"共 {len(articles)} 篇（原创）")
        else:
            task_log(task, "解析公众号 bookId ...")
            book_id, mp_name = resolve_book_id(cookie, keyword)
            task_log(task, f"  bookId = {book_id}")
            task_log(task, "拉取全部文章列表 ...")
            articles, got_name = fetch_all_articles(cookie, book_id, task=task,
                                                    max_articles=max_articles, on_page=_on_page,
                                                    date_from=date_from, date_to=date_to)
            if not mp_name and got_name:
                mp_name = got_name
        # 补全短链（可选）：正文抓取失败时可用短链直访回退
        if data.get("fetch_short_urls") and cookie and articles:
            save_name = f"{datetime.now().strftime('%y%m%d')}{sanitize(mp_name or book_id or '')}公众号文章链接.txt"
            attach_short_urls(cookie, articles, task=task, save_path=OUTPUT_ROOT / save_name)
            task["articles_sofar"] = list(articles)
        CACHE["articles"] = articles
        CACHE["book_id"] = book_id
        CACHE["mp_name"] = mp_name
        task["result"] = {"articles": articles, "book_id": book_id, "mp_name": mp_name}
        task["status"] = "done"
        task_log(task, f"拉取完成：共 {len(articles)} 篇文章" + (f"（{mp_name}）" if mp_name else ""))
    except TaskStopped:
        # 停止时保留已解析到的 bookId/mp_name，避免导出文件夹退化成「article」
        CACHE["book_id"] = book_id or CACHE.get("book_id", "")
        CACHE["mp_name"] = mp_name or CACHE.get("mp_name", "")
        task["status"] = "stopped"
        task["result"] = {"articles": task.get("articles_sofar") or [],
                          "book_id": book_id, "mp_name": mp_name}
        task_log(task, "已停止拉取")
    except Exception as e:
        task["status"] = "error"
        task["error"] = str(e)
        task_log(task, f"拉取失败：{e}")


@app.route("/api/articles", methods=["POST"])
def api_articles():
    data = request.get_json(force=True) or {}
    tid = new_task_id()
    with TASKS_LOCK:
        TASKS[tid] = {"status": "running", "log": [], "result": None, "error": None,
                      "cfg": data, "stop": False}
    threading.Thread(target=fetch_articles_worker, args=(tid,), daemon=True).start()
    return jsonify({"ok": True, "task_id": tid})


@app.route("/api/articles/stop", methods=["POST"])
def api_articles_stop():
    data = request.get_json(force=True) or {}
    tid = data.get("task_id") or ""
    task = TASKS.get(tid)
    if not task:
        return jsonify({"ok": False, "error": "任务不存在"})
    task["stop"] = True
    return jsonify({"ok": True})


@app.route("/api/comments", methods=["POST"])
def api_comments():
    data = request.get_json(force=True) or {}
    cred = {
        "token": data.get("token", ""),
        "fingerprint": data.get("fingerprint", ""),
        "cookie": data.get("mp_cookie", ""),
    }
    try:
        comment_articles = fetch_comment_articles(cred)
        results = []
        for ca in comment_articles:
            cid = ca.get("comment_id", "")
            try:
                meta = fetch_article_comments(cred, cid)
                results.append(meta)
            except Exception as e:
                results.append({"comment_id": cid, "title": "", "comments": [], "error": str(e)})
            time.sleep(0.4)
        CACHE["comments"] = {m.get("title", m.get("comment_id", "")): m for m in results}
        return jsonify({"ok": True, "articles": results})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})


@app.route("/api/export", methods=["POST"])
def api_export():
    data = request.get_json(force=True) or {}
    tid = new_task_id()
    with TASKS_LOCK:
        TASKS[tid] = {"status": "running", "log": [], "result": None, "error": None,
                      "cfg": data, "stop": False}
    threading.Thread(target=export_worker, args=(tid,), daemon=True).start()
    return jsonify({"ok": True, "task_id": tid})


@app.route("/api/export/stop", methods=["POST"])
def api_export_stop():
    data = request.get_json(force=True) or {}
    tid = data.get("task_id") or ""
    task = TASKS.get(tid)
    if not task:
        return jsonify({"ok": False, "error": "任务不存在"})
    task["stop"] = True
    return jsonify({"ok": True})


@app.route("/api/task/<tid>")
def api_task(tid):
    task = TASKS.get(tid)
    if not task:
        return jsonify({"ok": False, "error": "任务不存在"})
    return jsonify({"ok": True, "status": task["status"], "log": task["log"],
                    "result": task["result"], "error": task["error"],
                    "articles_sofar": task.get("articles_sofar", []),
                    "results_sofar": task.get("results_sofar", [])})


@app.route("/api/reader_capture/start", methods=["POST"])
def api_reader_capture_start():
    ok, msg = start_reader_capture()
    return jsonify({"ok": ok, "message": msg})


@app.route("/api/reader_capture/stop", methods=["POST"])
def api_reader_capture_stop():
    ok, msg = stop_reader_capture()
    return jsonify({"ok": ok, "message": msg})


@app.route("/api/reader_capture/status")
def api_reader_capture_status():
    return jsonify(_reader_capture_status())


@app.route("/api/reader/articles", methods=["POST"])
def api_reader_articles():
    """根据文章链接列表，抓取每篇的标题 + 发布时间，供「拉取文章列表」预览。"""
    data = request.get_json(force=True) or {}
    urls = [u.strip() for u in (data.get("article_urls") or []) if u and u.strip()]
    articles = []
    for i, url in enumerate(urls):
        item = {"url": url, "idx": i, "title": f"文章{i + 1}", "time": 0}
        try:
            raw_html = fetch_article_html_direct(url)
            title = extract_meta(raw_html, "og:title") or ""
            if title:
                item["title"] = title
            item["time"] = extract_publish_time(raw_html)
        except Exception as e:
            item["title"] = f"（抓取失败）{url[:40]}"
            item["error"] = str(e)
        articles.append(item)
        time.sleep(0.3)
    return jsonify({"ok": True, "articles": articles})


@app.route("/api/reader/mp_articles", methods=["POST"])
def api_reader_mp_articles():
    """载入勾选公众号在本次采集中打开的文章列表。"""
    data = request.get_json(force=True) or {}
    bizes = [b for b in (data.get("biz_list") or []) if b]
    if not bizes:
        return jsonify({"ok": False, "error": "请先勾选公众号"})
    creds = load_reader_credentials()
    arts = load_reader_articles()
    biz_set = set(bizes)
    articles = [{"title": a.get("title") or a.get("url", ""), "url": a.get("url", ""), "time": 0}
                for a in arts if a.get("biz") in biz_set and a.get("url")]
    names = [(creds.get(b) or {}).get("name") or b for b in bizes]
    return jsonify({"ok": True, "articles": articles, "names": names})


@app.route("/api/reader_export", methods=["POST"])
def api_reader_export():
    data = request.get_json(force=True) or {}
    tid = new_task_id()
    with TASKS_LOCK:
        TASKS[tid] = {"status": "running", "log": [], "result": None, "error": None,
                      "cfg": data, "stop": False}
    threading.Thread(target=reader_export_worker, args=(tid,), daemon=True).start()
    return jsonify({"ok": True, "task_id": tid})


@app.route("/api/reader_export/stop", methods=["POST"])
def api_reader_export_stop():
    data = request.get_json(force=True) or {}
    tid = data.get("task_id") or ""
    task = TASKS.get(tid)
    if not task:
        return jsonify({"ok": False, "error": "任务不存在"})
    task["stop"] = True
    return jsonify({"ok": True})


if __name__ == "__main__":
    load_config()
    print("=" * 56)
    print("微信公众号文章+评论导出工具已启动")
    print("浏览器将自动打开：http://127.0.0.1:5000")
    print("=" * 56)
    threading.Timer(1.2, lambda: webbrowser.open("http://127.0.0.1:5000")).start()
    app.run(host="127.0.0.1", port=5000, debug=False, threaded=True)
