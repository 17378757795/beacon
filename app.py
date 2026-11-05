"""Beacon 信标 - 局域网文件中转站

双击运行 → 弹出应用窗口 → 手机扫码 → 同一 WiFi 下互传文件，全程不过服务器。
"""

import io
import json
import logging
import math
import os
import queue
import re
import secrets
import shutil
import socket
import subprocess
import sys
import threading
import time
import uuid
import webbrowser
import zipfile
from hashlib import sha1
from pathlib import Path
from urllib.parse import quote

import qrcode
from flask import (Flask, Response, abort, jsonify, make_response, redirect,
                   render_template, request, send_file, stream_with_context)
from waitress import serve

APP_NAME = "Beacon"
APP_CN = "信标"
APP_VERSION = "2.4.6"
COOKIE = "beacon_token"
DEFAULT_PORT = 8765
CREATE_NO_WINDOW = 0x08000000
MAX_BODY = 8 * 1024 * 1024 * 1024
CHUNK_SIZE = 2 * 1024 * 1024
ZIP_CACHE_LIMIT = 1200 * 1024 * 1024
PHONE_TTL = 40
DESK_GRACE = 900

STATE = {
    "root": None,
    "desk_ping": None,
    "pages": {},
    "phones": {},
    "uploads": 0,
    "bytes": 0,
    "started": time.time(),
}
LOCK = threading.Lock()
UPLOAD_LOCK = threading.Lock()
UPLOADS: dict = {}


# ---------------------------------------------------------------- 路径与配置

def _base_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(getattr(sys, "_MEIPASS", Path(sys.executable).parent))
    return Path(__file__).resolve().parent


def _work_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


WORK = _work_dir()
CONFIG_PATH = WORK / "beacon.config.json"
CACHE_DIR = WORK / ".cache"
LOG_PATH = WORK / "beacon.log"


def setup_runtime() -> None:
    try:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
    except OSError:
        pass
    try:
        if LOG_PATH.exists() and LOG_PATH.stat().st_size > 2 * 1024 * 1024:
            LOG_PATH.unlink()
    except OSError:
        pass
    logging.basicConfig(
        filename=str(LOG_PATH), level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s", encoding="utf-8",
    )
    if sys.stdout is None or sys.stderr is None:
        try:
            handle = open(LOG_PATH, "a", encoding="utf-8", buffering=1)
            if sys.stdout is None:
                sys.stdout = handle
            if sys.stderr is None:
                sys.stderr = handle
        except OSError:
            pass


def load_config() -> dict:
    cfg = {}
    if CONFIG_PATH.exists():
        try:
            cfg = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
        except Exception:
            cfg = {}
    cfg.setdefault("token", secrets.token_urlsafe(9))
    cfg.setdefault("root", "")
    cfg.setdefault("port", 0)
    save_config(cfg)
    return cfg


def save_config(cfg: dict) -> None:
    try:
        CONFIG_PATH.write_text(json.dumps(cfg, ensure_ascii=False, indent=2), encoding="utf-8")
    except OSError:
        logging.warning("config write failed")


def writable_dir(path: Path) -> bool:
    try:
        path.mkdir(parents=True, exist_ok=True)
        probe = path / ".beacon_write_test"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
        return True
    except Exception:
        return False


def ensure_dirs(root: Path) -> None:
    try:
        root.mkdir(parents=True, exist_ok=True)
    except OSError:
        logging.warning("cannot create root %s", root)


def ensure_root(preferred: str = "") -> Path:
    candidates = []
    if preferred:
        candidates.append(Path(preferred))
    candidates.append(Path(os.environ.get("PUBLIC", r"C:\Users\Public")) / APP_NAME)
    candidates.append(Path(os.environ.get("USERPROFILE", str(Path.home()))) / APP_NAME)
    candidates.append(WORK / "SharedFiles")
    for c in candidates:
        if writable_dir(c):
            resolved = c.resolve()
            ensure_dirs(resolved)
            return resolved
    fallback = Path.cwd().resolve()
    ensure_dirs(fallback)
    return fallback


def lan_ip() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return "127.0.0.1"
    finally:
        s.close()


def free_port(preferred: int = 0) -> int:
    order = ([preferred] if preferred else []) + [DEFAULT_PORT, 0]
    for port in order:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("0.0.0.0", port))
            actual = s.getsockname()[1]
            s.close()
            if actual:
                return actual
        except OSError:
            continue
    return DEFAULT_PORT


ILLEGAL = re.compile(r'[<>:"/\\|?*\x00-\x1f]')


def clean_name(name: str) -> str:
    name = (name or "").replace("\\", "/").split("/")[-1]
    name = ILLEGAL.sub("_", name).strip().strip(".")
    return name or "未命名"


def safe_path(rel: str) -> Path:
    """把客户端传来的相对路径解析到共享目录内，越权一律拒绝。"""
    root = STATE["root"]
    raw = (rel or "").replace("\\", "/").strip()
    raw = re.sub(r"^[A-Za-z]:", "", raw)
    raw = raw.lstrip("/")
    if raw.startswith("//"):
        raw = raw.lstrip("/")
    try:
        target = (root / raw).resolve()
    except (OSError, ValueError):
        logging.warning("bad path: %r", rel)
        abort(400)
    try:
        same = os.path.commonpath([str(root), str(target)]) == str(root)
    except ValueError:
        logging.warning("cross-drive path rejected: %r", rel)
        abort(403)
    if not same:
        abort(403)
    return target


def unique_path(target: Path) -> Path:
    if not target.exists():
        return target
    stem, suffix = target.stem, target.suffix
    for i in range(1, 1000):
        cand = target.with_name(f"{stem} ({i}){suffix}")
        if not cand.exists():
            return cand
    return target.with_name(f"{stem}-{int(time.time())}{suffix}")


def human_size(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def free_bytes(path: Path) -> int:
    try:
        return shutil.disk_usage(path).free
    except OSError:
        return 0


def disk_guard(target: Path, need: int) -> str:
    free = free_bytes(target)
    if need and free < need + 80 * 1024 * 1024:
        return (f"磁盘空间不足：需要 {human_size(need)}，"
                f"{target.drive} 盘只剩 {human_size(free)}。"
                f"请点左下角「更改共享文件夹」换到空间大的盘。")
    return ""


def make_qr(url: str):
    qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M, box_size=10, border=2)
    qr.add_data(url)
    qr.make(fit=True)
    return qr.make_image(fill_color="#111827", back_color="white").convert("RGB")


def device_guess(ua: str) -> str:
    u = ua or ""
    if "iPhone" in u:
        return "iPhone / iOS Safari 内核"
    if "iPad" in u:
        return "iPad / iPadOS"
    if "Android" in u:
        return "Android / 微信内置浏览器" if "MicroMessenger" in u else "Android / 浏览器"
    if "MicroMessenger" in u:
        return "微信内置浏览器"
    if "Windows" in u:
        return "Windows 桌面浏览器"
    return "未知设备"


# ---------------------------------------------------------------- 应用

app = Flask(__name__, template_folder=str(_base_dir() / "templates"))
app.config["MAX_CONTENT_LENGTH"] = None
app.config["JSON_AS_ASCII"] = False

PUBLIC = {"/api/qr.png", "/favicon.ico", "/api/health",
          "/manifest.json", "/icon-192.png", "/icon-512.png"}


@app.before_request
def _auth():
    p = request.path
    if p in PUBLIC or p.startswith("/desk") or p.startswith("/static"):
        return None
    token = request.args.get("t") or request.cookies.get(COOKIE)
    if token != TOKEN:
        return make_response(
            "<meta charset='utf-8'><div style='font-family:system-ui;padding:48px;text-align:center;color:#334155'>"
            "<h3 style='font-weight:500'>需要扫码访问</h3>"
            "<p style='color:#94a3b8;font-size:14px'>请在电脑上打开 Beacon 窗口，用手机扫描二维码。</p></div>",
            403,
        )
    return None


def is_local() -> bool:
    return request.remote_addr in ("127.0.0.1", "::1")


def public_url() -> str:
    return f"http://{lan_ip()}:{PORT}/?t={TOKEN}"


@app.get("/")
def mobile():
    ua = request.headers.get("User-Agent", "")
    logging.info("phone page ip=%s device=%s", request.remote_addr, device_guess(ua))
    resp = make_response(render_template("mobile.html", app=APP_NAME))
    resp.set_cookie(COOKIE, TOKEN, max_age=86400 * 30, samesite="Lax")
    return resp


@app.get("/desk")
def desk():
    if not is_local():
        abort(403)
    resp = make_response(render_template(
        "desk.html", app=APP_NAME, cn=APP_CN, version=APP_VERSION, url=public_url()))
    resp.set_cookie(COOKIE, TOKEN, max_age=86400 * 30, samesite="Lax")
    return resp


@app.get("/admin")
def admin_legacy():
    return redirect("/desk")


@app.get("/help")
def help_page():
    resp = make_response(render_template("help.html"))
    resp.set_cookie(COOKIE, TOKEN, max_age=86400 * 30, samesite="Lax")
    return resp


@app.get("/api/health")
def health():
    return jsonify({"ok": True, "app": APP_NAME.lower(), "version": APP_VERSION})


@app.get("/api/whoami")
def whoami():
    ua = request.headers.get("User-Agent", "")
    return jsonify({"ok": True, "device": device_guess(ua), "ip": request.remote_addr, "ua": ua})


@app.get("/api/qr.png")
def qr_png():
    url = request.args.get("url") or public_url()
    buf = io.BytesIO()
    make_qr(url).save(buf, format="PNG")
    resp = make_response(buf.getvalue())
    resp.headers["Content-Type"] = "image/png"
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.get("/api/list")
def api_list():
    rel = request.args.get("p", "")
    d = safe_path(rel)
    if not d.exists() or not d.is_dir():
        return jsonify({"ok": False, "error": "目录不存在"}), 404
    items = []
    try:
        with os.scandir(d) as it:
            for entry in it:
                try:
                    st = entry.stat()
                    is_dir = entry.is_dir()
                    items.append({
                        "name": entry.name,
                        "dir": is_dir,
                        "role": "",
                        "size": 0 if is_dir else st.st_size,
                        "sizeText": "" if is_dir else human_size(st.st_size),
                        "mtime": int(st.st_mtime),
                        "ext": "" if is_dir else Path(entry.name).suffix.lower().lstrip("."),
                    })
                except OSError:
                    continue
    except PermissionError:
        return jsonify({"ok": False, "error": "没有权限读取该目录"}), 403
    items.sort(key=lambda x: (not x["dir"], x["name"].lower()))
    usage = shutil.disk_usage(STATE["root"])
    used_pct = round((usage.total - usage.free) / max(usage.total, 1) * 100)
    return jsonify({"ok": True, "path": rel, "items": items,
                    "free": human_size(usage.free), "total": human_size(usage.total),
                    "percent": used_pct, "root": str(STATE["root"]),
                    "phones": online_phones()})


@app.get("/api/space")
def api_space():
    target = safe_path(request.args.get("p", ""))
    while not target.exists() and target != target.parent:
        target = target.parent
    st = shutil.disk_usage(target)
    return jsonify({"ok": True, "free": st.free, "freeText": human_size(st.free),
                    "total": st.total, "drive": target.drive})


@app.post("/api/upload")
def api_upload():
    rel = request.form.get("p", "")
    d = safe_path(rel)
    d.mkdir(parents=True, exist_ok=True)
    files = [f for f in request.files.getlist("files") if f and f.filename]
    logging.info("upload start ip=%s target=%s files=%d", request.remote_addr, rel or "(root)", len(files))
    saved = []
    for f in files:
        need = f.content_length or 0
        err = disk_guard(d, need)
        if err:
            logging.warning("disk full: %s", err)
            return jsonify({"ok": False, "error": err}), 507
        with UPLOAD_LOCK:
            target = unique_path(d / clean_name(f.filename))
            try:
                f.save(str(target))
            except OSError as e:
                if target.exists():
                    try:
                        target.unlink()
                    except OSError:
                        pass
                logging.warning("save failed: %s", e)
                return jsonify({"ok": False, "error": f"保存失败：{e}（可能是磁盘空间不足）"}), 507
        size = target.stat().st_size
        saved.append({"name": target.name, "size": size})
        with LOCK:
            STATE["uploads"] += 1
            STATE["bytes"] += size
    logging.info("upload done count=%d bytes=%d", len(saved), sum(x["size"] for x in saved))
    touch_phone()
    return jsonify({"ok": True, "saved": saved, "count": len(saved)})


def _tmp_dir() -> Path:
    p = CACHE_DIR / "tmp"
    p.mkdir(parents=True, exist_ok=True)
    return p


@app.post("/api/upload/init")
def api_upload_init():
    data = request.get_json(silent=True) or {}
    rel = data.get("p") or ""
    d = safe_path(rel)
    d.mkdir(parents=True, exist_ok=True)
    name = clean_name(data.get("name") or "")
    size = int(data.get("size") or 0)
    if size <= 0:
        return jsonify({"ok": False, "error": "文件为空"}), 400
    err = disk_guard(d, size)
    if err:
        logging.warning("disk full on init: %s", err)
        return jsonify({"ok": False, "error": err}), 507
    uid = uuid.uuid4().hex
    part = _tmp_dir() / f"{uid}.part"
    part.write_bytes(b"")
    chunks = max(1, math.ceil(size / CHUNK_SIZE))
    UPLOADS[uid] = {"path": part, "name": name, "size": size, "dir": d,
                    "chunks": chunks, "received": set(), "lock": threading.Lock(),
                    "ts": time.time()}
    logging.info("chunk init id=%s name=%s size=%d chunks=%d", uid[:8], name, size, chunks)
    return jsonify({"ok": True, "id": uid, "chunk": CHUNK_SIZE, "chunks": chunks})


@app.post("/api/upload/chunk")
def api_upload_chunk():
    uid = request.form.get("id") or ""
    try:
        idx = int(request.form.get("index") or 0)
    except ValueError:
        return jsonify({"ok": False, "error": "序号错误"}), 400
    entry = UPLOADS.get(uid)
    if not entry:
        return jsonify({"ok": False, "error": "上传会话已失效，请重试"}), 410
    blob = request.files.get("data")
    if blob is None:
        return jsonify({"ok": False, "error": "缺少数据"}), 400
    payload = blob.read()
    if idx >= entry["chunks"]:
        return jsonify({"ok": False, "error": "序号越界"}), 400
    with entry["lock"]:
        try:
            with open(entry["path"], "r+b") as fh:
                fh.seek(idx * CHUNK_SIZE)
                fh.write(payload)
        except OSError as e:
            logging.warning("chunk write failed: %s", e)
            return jsonify({"ok": False, "error": f"写入失败：{e}（磁盘可能已满）"}), 507
        entry["received"].add(idx)
    return jsonify({"ok": True, "received": len(entry["received"]), "chunks": entry["chunks"]})


@app.post("/api/upload/finish")
def api_upload_finish():
    data = request.get_json(silent=True) or {}
    uid = data.get("id") or ""
    entry = UPLOADS.get(uid)
    if not entry:
        return jsonify({"ok": False, "error": "上传会话已失效，请重试"}), 410
    missing = entry["chunks"] - len(entry["received"])
    if missing > 0:
        return jsonify({"ok": False, "error": f"还差 {missing} 个分片，请重试"}), 400
    UPLOADS.pop(uid, None)
    actual = entry["path"].stat().st_size
    with UPLOAD_LOCK:
        target = unique_path(entry["dir"] / entry["name"])
        shutil.move(str(entry["path"]), str(target))
        final = target
    with LOCK:
        STATE["uploads"] += 1
        STATE["bytes"] += actual
    logging.info("chunk done name=%s bytes=%d", final.name, actual)
    touch_phone()
    return jsonify({"ok": True, "name": final.name, "size": actual})


def cleanup_uploads() -> None:
    now = time.time()
    for uid, entry in list(UPLOADS.items()):
        if now - entry["ts"] > 7200:
            UPLOADS.pop(uid, None)
            try:
                entry["path"].unlink(missing_ok=True)
            except OSError:
                pass
    zdir = CACHE_DIR / "zip"
    if zdir.exists():
        for f in zdir.iterdir():
            try:
                if f.suffix == ".part" and now - f.stat().st_mtime > 600:
                    f.unlink()
                elif f.suffix == ".zip" and now - f.stat().st_mtime > 3600:
                    f.unlink()
            except OSError:
                continue


@app.post("/api/mkdir")
def api_mkdir():
    data = request.get_json(silent=True) or {}
    parent = safe_path(data.get("p", ""))
    name = clean_name(data.get("name", ""))
    if not name or name in (".", ".."):
        return jsonify({"ok": False, "error": "名称不合法"}), 400
    target = parent / name
    if target.exists():
        return jsonify({"ok": False, "error": "同名文件夹已存在"}), 409
    target.mkdir(parents=True, exist_ok=True)
    return jsonify({"ok": True, "name": name})


@app.post("/api/rename")
def api_rename():
    data = request.get_json(silent=True) or {}
    src = safe_path(data.get("p", ""))
    if src == STATE["root"] or not src.exists():
        return jsonify({"ok": False, "error": "文件不存在"}), 404
    new_name = clean_name(data.get("name", ""))
    if not new_name:
        return jsonify({"ok": False, "error": "名称不合法"}), 400
    dst = src.with_name(new_name)
    same_file = str(dst).lower() == str(src).lower()
    if dst.exists() and not same_file:
        return jsonify({"ok": False, "error": "同名文件已存在"}), 409
    if same_file and dst.name == src.name:
        return jsonify({"ok": True, "name": src.name})
    src.rename(dst)
    return jsonify({"ok": True, "name": dst.name})


def move_to_trash(target: Path) -> bool:
    """删除时先送系统回收站（可还原）；失败返回 False。"""
    if os.name != "nt":
        return False
    try:
        import ctypes
        from ctypes import wintypes

        class SHFILEOPSTRUCTW(ctypes.Structure):
            _fields_ = [
                ("hwnd", wintypes.HWND),
                ("wFunc", wintypes.UINT),
                ("pFrom", wintypes.LPCWSTR),
                ("pTo", wintypes.LPCWSTR),
                ("fFlags", ctypes.c_uint16),
                ("fAnyOperationsAborted", wintypes.BOOL),
                ("hNameMappings", ctypes.c_void_p),
                ("lpszProgressTitle", wintypes.LPCWSTR),
            ]

        FO_DELETE = 3
        FOF_ALLOWUNDO = 0x0040
        FOF_NOCONFIRMATION = 0x0010
        FOF_SILENT = 0x0004
        FOF_NOERRORUI = 0x0400

        op = SHFILEOPSTRUCTW()
        op.hwnd = None
        op.wFunc = FO_DELETE
        op.pFrom = str(target) + "\0"
        op.pTo = None
        op.fFlags = FOF_ALLOWUNDO | FOF_NOCONFIRMATION | FOF_SILENT | FOF_NOERRORUI
        code = ctypes.windll.shell32.SHFileOperationW(ctypes.byref(op))
        if code != 0:
            logging.warning("trash returned %s for %s", code, target)
            return False
        return not target.exists()
    except Exception as e:
        logging.warning("trash failed: %s", e)
        return False


def hard_delete(target: Path):
    """尽力删除，返回 (成功数, 失败数, 失败样例)。"""
    ok = err = 0
    samples = []
    if target.is_file():
        try:
            os.chmod(target, 0o666)
            target.unlink()
            return 1, 0, []
        except OSError as e:
            return 0, 1, [f"{target.name}: {e.strerror or e}"]
    for root, dirs, files in os.walk(target, topdown=False):
        for fn in files:
            fp = os.path.join(root, fn)
            try:
                os.chmod(fp, 0o666)
                os.unlink(fp)
                ok += 1
            except OSError as e:
                err += 1
                if len(samples) < 3:
                    samples.append(f"{fn}: {e.strerror or e}")
        for d in dirs:
            try:
                os.rmdir(os.path.join(root, d))
            except OSError:
                pass
    try:
        os.rmdir(target)
    except OSError:
        pass
    return ok, err, samples


@app.post("/api/delete")
def api_delete():
    data = request.get_json(silent=True) or {}
    target = safe_path(data.get("p", ""))
    if target == STATE["root"]:
        return jsonify({"ok": False, "error": "不能删除根目录"}), 400
    if not target.exists():
        return jsonify({"ok": False, "error": "文件不存在"}), 404

    if move_to_trash(target):
        logging.info("deleted to trash: %s", target)
        return jsonify({"ok": True, "trash": True})

    ok, err, samples = hard_delete(target)
    if err == 0 and not target.exists():
        logging.info("deleted permanently: %s", target)
        return jsonify({"ok": True, "trash": False})

    logging.warning("partial delete %s: ok=%d err=%d", target, ok, err)
    msg = f"已删除 {ok} 个文件，还有 {err} 个被占用或没有权限，删不掉。"
    if samples:
        msg += "（" + samples[0] + "）"
    msg += " 常见原因是下载器/杀毒软件正占用这些文件，关掉它们或重启电脑后再删。"
    return jsonify({"ok": False, "partial": True, "deleted": ok, "failed": err,
                    "error": msg}), 409


@app.get("/f")
def download():
    target = safe_path(request.args.get("p", ""))
    if not target.is_file():
        abort(404)
    inline = request.args.get("inline") == "1"
    return send_file(target, as_attachment=not inline, download_name=target.name, conditional=True)


@app.get("/api/thumb")
def thumb():
    target = safe_path(request.args.get("p", ""))
    if not target.is_file():
        abort(404)
    try:
        st = target.stat()
        key = sha1(f"{target}|{st.st_mtime}|{st.st_size}".encode("utf-8")).hexdigest()[:20]
        cached = CACHE_DIR / f"{key}.jpg"
        if not cached.exists():
            from PIL import Image
            img = Image.open(target)
            img = img.convert("RGB")
            img.thumbnail((180, 180))
            img.save(cached, "JPEG", quality=72)
        return send_file(cached, mimetype="image/jpeg", max_age=86400)
    except Exception:
        abort(404)


class _QueueSink:
    """给 zipfile 用的只写流：写满一块就入队，配合生成器边压边发。"""

    BLOCK = 1 << 20

    def __init__(self, q, stop):
        self.q = q
        self.stop = stop
        self.buf = bytearray()

    def write(self, data) -> int:
        self.buf += data
        while len(self.buf) >= self.BLOCK:
            self._emit(bytes(self.buf[:self.BLOCK]))
            del self.buf[:self.BLOCK]
        return len(data)

    def _emit(self, block: bytes) -> None:
        while True:
            if self.stop.is_set():
                raise BrokenPipeError("client gone")
            try:
                self.q.put(block, timeout=1)
                return
            except queue.Full:
                continue

    def flush(self) -> None:
        pass

    def tell(self):
        raise OSError("unseekable")

    def seekable(self) -> bool:
        return False

    def close(self) -> None:
        if self.buf:
            self._emit(bytes(self.buf))
            self.buf.clear()


def _folder_stats(target: Path):
    total = 0
    count = 0
    for base, _dirs, files in os.walk(target):
        for fn in files:
            try:
                total += os.path.getsize(os.path.join(base, fn))
                count += 1
            except OSError:
                continue
    return total, count


@app.get("/api/size")
def api_size():
    target = safe_path(request.args.get("p", ""))
    if not target.exists():
        return jsonify({"ok": False, "error": "不存在"}), 404
    if target.is_dir():
        total, count = _folder_stats(target)
    else:
        total, count = target.stat().st_size, 1
    return jsonify({"ok": True, "size": total, "sizeText": human_size(total), "count": count})


def _build_zip_file(target: Path, zpath: Path) -> None:
    tmp = zpath.with_suffix(".part")
    with zipfile.ZipFile(tmp, "w", zipfile.ZIP_STORED, allowZip64=True) as zf:
        base_parent = target.parent
        for root_dir, _dirs, files in os.walk(target):
            for fn in sorted(files):
                full = Path(root_dir) / fn
                try:
                    arc = str(full.relative_to(base_parent))
                except ValueError:
                    arc = fn
                try:
                    zf.write(full, arc)
                except OSError:
                    continue
    tmp.replace(zpath)


@app.get("/zip")
def zip_folder():
    """小文件夹先落成 zip 缓存（有总大小、可续传）；大文件夹流式发送。"""
    target = safe_path(request.args.get("p", ""))
    if not target.is_dir():
        abort(404)
    arc_name = f"{clean_name(target.name)}.zip"
    total, count = _folder_stats(target)

    if total <= ZIP_CACHE_LIMIT:
        try:
            st = target.stat()
            key = sha1(f"{target}|{total}|{count}|{int(st.st_mtime)}".encode("utf-8")).hexdigest()[:16]
            zdir = CACHE_DIR / "zip"
            zdir.mkdir(parents=True, exist_ok=True)
            zpath = zdir / f"{key}.zip"
            if not zpath.exists():
                logging.info("zip build start dir=%s files=%d size=%d", target.name, count, total)
                _build_zip_file(target, zpath)
                logging.info("zip build done %s", zpath.name)
            resp = send_file(zpath, as_attachment=True, download_name=arc_name, conditional=True)
            resp.headers["Content-Disposition"] = "attachment; filename*=UTF-8''" + quote(arc_name)
            return resp
        except OSError as e:
            logging.warning("zip cache failed, fallback to stream: %s", e)

    base_parent = target.parent

    def generate():
        q: "queue.Queue" = queue.Queue(maxsize=8)
        stop = threading.Event()

        def producer():
            try:
                sink = _QueueSink(q, stop)
                with zipfile.ZipFile(sink, "w", zipfile.ZIP_STORED, allowZip64=True) as zf:
                    for root_dir, _dirs, files in os.walk(target):
                        for fn in sorted(files):
                            full = Path(root_dir) / fn
                            try:
                                arc = str(full.relative_to(base_parent))
                            except ValueError:
                                arc = fn
                            try:
                                zf.write(full, arc)
                            except OSError:
                                continue
                sink.close()
                logging.info("zip stream done dir=%s", target.name)
            except (BrokenPipeError, ConnectionResetError):
                pass
            except Exception as e:
                logging.warning("zip failed: %s", e)
            finally:
                try:
                    q.put(None, timeout=60)
                except Exception:
                    pass

        threading.Thread(target=producer, daemon=True).start()
        try:
            while True:
                item = q.get()
                if item is None:
                    break
                yield item
        finally:
            stop.set()

    resp = Response(stream_with_context(generate()), mimetype="application/zip")
    resp.headers["Content-Disposition"] = "attachment; filename*=UTF-8''" + quote(arc_name)
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.post("/api/root")
def api_set_root():
    if not is_local():
        abort(403)
    data = request.get_json(silent=True) or {}
    raw = (data.get("path") or "").strip().strip('"')
    if not raw:
        return jsonify({"ok": False, "error": "路径为空"}), 400
    p = Path(raw).expanduser()
    if not p.is_absolute():
        return jsonify({"ok": False, "error": "请填写完整路径，例如 D:\\共享"}), 400
    if not writable_dir(p):
        return jsonify({"ok": False, "error": "这个目录不可写，换一个试试"}), 400
    STATE["root"] = p.resolve()
    ensure_dirs(STATE["root"])
    CFG["root"] = str(STATE["root"])
    save_config(CFG)
    return jsonify({"ok": True, "root": str(STATE["root"])})


@app.get("/api/pickfolder")
def api_pickfolder():
    if not is_local():
        abort(403)
    ps = (
        "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8;"
        "Add-Type -AssemblyName System.Windows.Forms;"
        "$d=New-Object System.Windows.Forms.FolderBrowserDialog;"
        "$d.Description='选择要共享的文件夹';"
        "$d.ShowNewFolderButton=$true;"
        "if($d.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK){$d.SelectedPath}"
    )
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-STA", "-Command", ps],
            capture_output=True, timeout=180, creationflags=CREATE_NO_WINDOW,
        )
        path = out.stdout.decode("utf-8", "replace").strip()
        if not path:
            return jsonify({"ok": False, "error": "未选择目录"})
        return jsonify({"ok": True, "path": path})
    except Exception as e:
        logging.warning("pickfolder failed: %s", e)
        return jsonify({"ok": False, "error": "无法打开选择框，请手动填写路径"})


@app.post("/api/open")
def api_open():
    if not is_local():
        abort(403)
    data = request.get_json(silent=True) or {}
    target = safe_path(data.get("p", ""))
    if not target.exists():
        return jsonify({"ok": False, "error": "文件不存在"}), 404
    try:
        os.startfile(str(target))
    except Exception as e:
        return jsonify({"ok": False, "error": f"打不开：{e}"}), 500
    return jsonify({"ok": True})


@app.post("/api/ping")
def api_ping():
    touch_phone()
    return jsonify({"ok": True, "phones": online_phones()})


def touch_phone() -> None:
    with LOCK:
        STATE["phones"][request.remote_addr] = time.time()


def online_phones() -> int:
    now = time.time()
    with LOCK:
        STATE["phones"] = {ip: ts for ip, ts in STATE["phones"].items() if now - ts < PHONE_TTL}
        return len(STATE["phones"])


@app.post("/api/desk/ping")
def api_desk_ping():
    if not is_local():
        abort(403)
    pid = request.args.get("pid") or "default"
    with LOCK:
        STATE["pages"][pid] = time.time()
    STATE["desk_ping"] = time.time()
    return jsonify({"ok": True, "phones": online_phones(),
                    "root": str(STATE["root"]), "pages": live_pages()})


def live_pages() -> int:
    now = time.time()
    with LOCK:
        STATE["pages"] = {k: v for k, v in STATE["pages"].items() if now - v < 25}
        return len(STATE["pages"])


@app.post("/api/desk/bye")
def api_desk_bye():
    return jsonify({"ok": True})


@app.post("/api/shutdown")
def api_shutdown():
    if not is_local():
        abort(403)
    threading.Thread(target=lambda: (time.sleep(0.4), os._exit(0)), daemon=True).start()
    return jsonify({"ok": True})


@app.get("/favicon.ico")
def favicon():
    return ("", 204)


@app.errorhandler(Exception)
def handle_error(e):
    from werkzeug.exceptions import HTTPException
    code = 500
    if isinstance(e, HTTPException):
        code = e.code or 500
        msg = e.description or e.name
    else:
        msg = f"{type(e).__name__}: {e}"
        logging.exception("unhandled error on %s", request.path)
    if request.path.startswith("/api/") or request.path in ("/zip", "/f"):
        return jsonify({"ok": False, "error": msg}), code
    if isinstance(e, HTTPException):
        return e.get_response()
    return "服务器内部错误，详情见 beacon.log", 500


@app.get("/manifest.json")
def manifest():
    body = {
        "name": f"{APP_CN} {APP_NAME}",
        "short_name": APP_CN,
        "start_url": "/?t=" + TOKEN,
        "scope": "/",
        "display": "standalone",
        "background_color": "#f6f8fb",
        "theme_color": "#ffffff",
        "orientation": "portrait",
        "icons": [
            {"src": "/icon-192.png", "sizes": "192x192", "type": "image/png", "purpose": "any"},
            {"src": "/icon-512.png", "sizes": "512x512", "type": "image/png", "purpose": "any"},
        ],
    }
    resp = make_response(json.dumps(body, ensure_ascii=False))
    resp.headers["Content-Type"] = "application/manifest+json; charset=utf-8"
    return resp


@app.get("/icon-<int:size>.png")
def app_icon(size):
    if size not in (192, 512):
        abort(404)
    path = _base_dir() / "icons" / f"icon-{size}.png"
    if not path.exists():
        abort(404)
    return send_file(path, mimetype="image/png", max_age=86400)


# ---------------------------------------------------------------- 窗口与守卫

def find_browser():
    candidates = [
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    ]
    for c in candidates:
        if Path(c).exists():
            return c
    return None


def open_window(url: str) -> None:
    exe = find_browser()
    if exe:
        try:
            subprocess.Popen([exe, f"--app={url}", "--window-size=1200,800",
                              "--no-first-run", "--no-default-browser-check"],
                             creationflags=CREATE_NO_WINDOW, close_fds=True)
            return
        except Exception as e:
            logging.warning("window launch failed: %s", e)
    webbrowser.open(url)


def run_window() -> None:
    """原生窗口外壳：关窗即退出。"""
    try:
        import webview
    except Exception as e:
        logging.warning("pywebview unavailable (%s), fallback to browser window", e)
        open_window(f"http://127.0.0.1:{PORT}/desk")
        while True:
            time.sleep(3600)

    webview.create_window(
        f"{APP_CN} {APP_NAME}",
        f"http://127.0.0.1:{PORT}/desk",
        width=1200, height=800, min_size=(960, 620),
        background_color="#0f172a",
    )
    webview.start()
    logging.info("window closed, exiting")
    os._exit(0)


def watchdog() -> None:
    while True:
        time.sleep(30)
        cleanup_uploads()
        last = STATE.get("desk_ping")
        if last and time.time() - last > DESK_GRACE:
            logging.info("idle too long, exiting")
            os._exit(0)


def already_running(port: int) -> bool:
    if not port:
        return False
    try:
        import urllib.request
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(f"http://127.0.0.1:{port}/api/health", timeout=1.5) as r:
            data = json.loads(r.read().decode("utf-8"))
        return data.get("app") == APP_NAME.lower()
    except Exception:
        return False


def _serve() -> None:
    try:
        serve(app, host="0.0.0.0", port=PORT, threads=16,
              channel_timeout=1800, max_request_body_size=MAX_BODY)
    except Exception as e:
        logging.error("serve failed: %s", e)
        os._exit(1)


def wait_ready(timeout: float = 8.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", PORT), timeout=0.4):
                return
        except OSError:
            time.sleep(0.15)


def fatal(msg: str) -> None:
    logging.error("fatal: %s", msg)
    try:
        import ctypes
        ctypes.windll.user32.MessageBoxW(0, msg, f"{APP_NAME} 启动失败", 0x10)
    except Exception:
        pass


PORT = 0
CFG = {}
TOKEN = ""


def main() -> None:
    global PORT, CFG, TOKEN
    try:
        setup_runtime()
        CFG = load_config()
        TOKEN = CFG["token"]

        cfg_port = int(CFG.get("port") or 0)
        if already_running(cfg_port):
            PORT = cfg_port
            print(f"[{APP_NAME}] already running on {PORT}", flush=True)
            if "--no-window" in sys.argv:
                return
            run_window()
            return

        STATE["root"] = ensure_root(CFG.get("root", ""))
        PORT = free_port(cfg_port)
        CFG["port"] = PORT
        save_config(CFG)

        print(f"[{APP_NAME} {APP_VERSION}] root={STATE['root']} port={PORT}", flush=True)
        print(f"[{APP_NAME}] phone url = {public_url()}", flush=True)

        threading.Thread(target=_serve, daemon=True).start()
        threading.Thread(target=watchdog, daemon=True).start()
        wait_ready()

        if "--no-window" in sys.argv:
            while True:
                time.sleep(3600)
        run_window()
    except KeyboardInterrupt:
        pass
    except Exception as e:
        import traceback
        logging.error("startup error: %s\n%s", e, traceback.format_exc())
        fatal(f"程序启动失败：{e}\n\n详细信息见同目录 beacon.log")
        raise


if __name__ == "__main__":
    main()
