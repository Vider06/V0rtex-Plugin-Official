# V0RTEX Plugin
# Name: V0RTEX Test Plugin
# Version: 2.0.0
# Author: Vider_06
# Description: Developer test plugin — exercises every lifecycle hook, every Verified API call, and every Elevated API call
# Dependencies: none
# Class: Elevated
# Elevated-Permissions: fs.read.external, fs.write.zip, fs.write.json, fs.write.xml, fs.write.csv, fs.write.html, fs.write.pdf, fs.read.v0rtex.logs, fs.read.v0rtex.reports, net.background, net.listen, proc.read, sys.read.registry, sys.read.env
# Background-Network: no
# Background-Endpoints: none
# Min-V0RTEX-Version: 1.0.1

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import time

_win        = None
_log_lines  = []
_scan_cb_id = None
_srv_socket = None


def _log(msg):
    ts = time.strftime("%H:%M:%S")
    entry = f"[{ts}] {msg}"
    _log_lines.append(entry)
    if _win and _win.winfo_exists():
        try:
            _txt.config(state="normal")
            _txt.insert("end", entry + "\n")
            _txt.see("end")
            _txt.config(state="disabled")
        except Exception:
            pass


def on_load():
    global _scan_cb_id
    _log("on_load() called")
    if hasattr(vx, "scan") and hasattr(vx.scan, "on_scan_complete"):
        _scan_cb_id = vx.scan.on_scan_complete(_on_scan_complete)
        _log("Registered scan callback via vx.scan.on_scan_complete()")
    _log("Plugin initialised — run() will open the test window")


def run():
    _log("run() called — building UI")
    _build_window()


def on_unload():
    global _win, _srv_socket
    _log("on_unload() called — cleaning up")
    if _srv_socket is not None:
        try:
            _srv_socket.close()
            _log("net.listen socket closed")
        except Exception:
            pass
        _srv_socket = None
    if _win and _win.winfo_exists():
        try:
            _win.destroy()
        except Exception:
            pass
    _win = None
    _log_lines.clear()


def on_update(old_version, new_version):
    _log(f"on_update() called: {old_version} → {new_version}")
    messagebox.showinfo(
        "Plugin Updated",
        f"V0RTEX Test Plugin updated from v{old_version} to v{new_version}.",
        parent=root,
    )


def _on_scan_complete(result):
    _log(f"[CALLBACK] vx.scan.on_scan_complete fired — file: {result.get('file', '?')}")


def _build_window():
    global _win, _txt

    if _win and _win.winfo_exists():
        _win.lift()
        return

    theme   = vx.ui.get_theme()
    bg      = theme.get("bg",      "#1e1e2e")
    surface = theme.get("surface", "#313244")
    fg      = theme.get("fg",      "#cdd6f4")
    accent  = theme.get("accent",  "#89b4fa")
    green   = theme.get("green",   "#a6e3a1")
    red     = theme.get("red",     "#f38ba8")
    yellow  = theme.get("yellow",  "#f9e2af")
    mauve   = theme.get("mauve",   "#cba6f7")
    teal    = theme.get("teal",    "#94e2d5")
    font_ui = theme.get("font",    "Consolas")

    _win = tk.Toplevel(root)
    _win.title("V0RTEX Test Plugin v2 — Full API & Lifecycle Tester")
    _win.configure(bg=bg)
    _win.resizable(True, True)
    _win.geometry("1020x680")
    _win.minsize(820, 520)

    def _mkbtn(parent, label, cmd, color):
        b = tk.Button(
            parent, text=label, command=cmd,
            bg=color, fg=bg, font=(font_ui, 9, "bold"),
            relief="flat", bd=0, padx=8, pady=5, cursor="hand2",
            activebackground=fg, activeforeground=bg,
        )
        b.pack(side="left", padx=3, pady=4)
        return b

    hdr = tk.Frame(_win, bg=surface)
    hdr.pack(fill="x")
    tk.Label(
        hdr,
        text="  🧪  V0RTEX Test Plugin  —  Full API & Lifecycle Tester  [Elevated]",
        bg=surface, fg=accent, font=(font_ui, 11, "bold"), anchor="w",
    ).pack(side="left", padx=8, pady=8)
    tk.Label(
        hdr, text="v2.0.0", bg=surface, fg=yellow, font=(font_ui, 9),
    ).pack(side="right", padx=12, pady=8)

    paned = tk.PanedWindow(_win, orient="horizontal", bg=bg, sashwidth=4, sashrelief="flat")
    paned.pack(fill="both", expand=True, padx=8, pady=6)

    left_scroll_frame = tk.Frame(paned, bg=bg)
    paned.add(left_scroll_frame, minsize=340)

    left_canvas = tk.Canvas(left_scroll_frame, bg=bg, highlightthickness=0)
    left_sb = ttk.Scrollbar(left_scroll_frame, orient="vertical", command=left_canvas.yview)
    left_canvas.configure(yscrollcommand=left_sb.set)
    left_sb.pack(side="right", fill="y")
    left_canvas.pack(side="left", fill="both", expand=True)

    left = tk.Frame(left_canvas, bg=bg)
    left_win_id = left_canvas.create_window((0, 0), window=left, anchor="nw")

    def _on_left_configure(e):
        left_canvas.configure(scrollregion=left_canvas.bbox("all"))
    def _on_canvas_configure(e):
        left_canvas.itemconfig(left_win_id, width=e.width)
    left.bind("<Configure>", _on_left_configure)
    left_canvas.bind("<Configure>", _on_canvas_configure)

    right_frame = tk.Frame(paned, bg=bg)
    paned.add(right_frame, minsize=320)

    def _section(title, color=None):
        lbl_color = color or accent
        f = tk.LabelFrame(
            left, text=f"  {title}  ",
            bg=bg, fg=lbl_color,
            font=(font_ui, 9, "bold"),
            relief="groove", bd=1, labelanchor="nw",
        )
        f.pack(fill="x", padx=4, pady=(0, 6))
        return f

    sec_ui = _section("vx.ui — UI API")
    _mkbtn(sec_ui, "notify info",    lambda: _btn_notify("info"),    green)
    _mkbtn(sec_ui, "notify warning", lambda: _btn_notify("warning"), yellow)
    _mkbtn(sec_ui, "notify error",   lambda: _btn_notify("error"),   red)

    sec_theme = _section("vx.ui.get_theme()")
    _mkbtn(sec_theme, "Show Theme", _btn_show_theme, accent)

    sec_ver = _section("vx.version.get()")
    _mkbtn(sec_ver, "Get V0RTEX Version", _btn_version, accent)

    sec_scan = _section("vx.scan")
    _mkbtn(sec_scan, "last result",  _btn_last_result, green)
    _mkbtn(sec_scan, "get history",  _btn_history,     accent)

    sec_ioc = _section("vx.ioc")
    _mkbtn(sec_ioc, "last IOCs", _btn_ioc, accent)

    sec_notes = _section("vx.notes")
    _mkbtn(sec_notes, "Append note", _btn_notes, green)

    sec_lc = _section("Lifecycle")
    _mkbtn(sec_lc, "simulate on_update", lambda: on_update("2.0.0", "2.0.1"), yellow)

    sep = tk.Frame(left, bg=surface, height=2)
    sep.pack(fill="x", padx=4, pady=6)
    tk.Label(
        left, text="  ⚡ Elevated API",
        bg=bg, fg=mauve, font=(font_ui, 9, "bold"), anchor="w",
    ).pack(fill="x", padx=4, pady=(0, 4))

    sec_fs_re = _section("vx.fs.read_external(path)", color=mauve)
    _mkbtn(sec_fs_re, "Pick & Read File", _btn_fs_read_external, mauve)

    sec_fs_wf = _section("vx.fs.write_file(name, data, fmt)", color=mauve)
    btn_row1 = tk.Frame(sec_fs_wf, bg=bg)
    btn_row1.pack(anchor="w")
    _mkbtn(btn_row1, "write json", lambda: _btn_fs_write("json"), mauve)
    _mkbtn(btn_row1, "write csv",  lambda: _btn_fs_write("csv"),  mauve)
    _mkbtn(btn_row1, "write xml",  lambda: _btn_fs_write("xml"),  mauve)
    btn_row2 = tk.Frame(sec_fs_wf, bg=bg)
    btn_row2.pack(anchor="w")
    _mkbtn(btn_row2, "write html", lambda: _btn_fs_write("html"), mauve)
    _mkbtn(btn_row2, "write pdf",  lambda: _btn_fs_write("pdf"),  teal)
    _mkbtn(btn_row2, "write zip",  lambda: _btn_fs_write("zip"),  teal)

    sec_fs_logs = _section("vx.fs.read_logs()", color=mauve)
    _mkbtn(sec_fs_logs, "Read Logs", _btn_fs_read_logs, mauve)

    sec_fs_rep = _section("vx.fs.read_reports()", color=mauve)
    _mkbtn(sec_fs_rep, "Read Reports", _btn_fs_read_reports, mauve)

    sec_net_bg = _section("vx.net.background_request(method, url)", color=teal)
    _mkbtn(sec_net_bg, "GET httpbin.org/get", _btn_net_bg_request, teal)

    sec_net_ls = _section("vx.net.listen(host, port, handler)", color=teal)
    _mkbtn(sec_net_ls, "Start Listener :19876", _btn_net_listen,     teal)
    _mkbtn(sec_net_ls, "Close Listener",        _btn_net_listen_stop, red)

    sec_proc = _section("vx.proc.list_processes()", color=yellow)
    _mkbtn(sec_proc, "List Processes", _btn_proc_list, yellow)

    sec_reg = _section("vx.sys.read_registry(key, value=None)", color=yellow)
    _mkbtn(sec_reg, "Read Registry Key", _btn_sys_registry, yellow)

    sec_env = _section("vx.sys.read_env()", color=yellow)
    _mkbtn(sec_env, "Read Env Vars", _btn_sys_env, yellow)

    sep2 = tk.Frame(left, bg=surface, height=2)
    sep2.pack(fill="x", padx=4, pady=6)
    _mkbtn(left, "Clear Log", _clear_log, red)
    tk.Frame(left, bg=bg, height=8).pack()

    tk.Label(
        right_frame, text="Event Log", bg=bg, fg=accent,
        font=(font_ui, 9, "bold"), anchor="w",
    ).pack(fill="x")

    log_frame = tk.Frame(right_frame, bg=surface, bd=1, relief="sunken")
    log_frame.pack(fill="both", expand=True)

    _txt = tk.Text(
        log_frame,
        bg=surface, fg=fg, font=(font_ui, 9),
        state="disabled", wrap="word",
        relief="flat", bd=0,
        selectbackground=accent, selectforeground=bg,
    )
    sb2 = ttk.Scrollbar(log_frame, command=_txt.yview)
    _txt.configure(yscrollcommand=sb2.set)
    sb2.pack(side="right", fill="y")
    _txt.pack(fill="both", expand=True, padx=4, pady=4)

    for line in _log_lines:
        _txt.config(state="normal")
        _txt.insert("end", line + "\n")
        _txt.config(state="disabled")
    _txt.see("end")

    _log("Window built — all controls ready")


def _btn_notify(level):
    msgs = {
        "info":    "Test info notification from plugin ✓",
        "warning": "Test warning notification from plugin ⚠",
        "error":   "Test error notification from plugin ✗",
    }
    vx.ui.notify(msgs[level], level)
    _log(f"vx.ui.notify(level={level!r}) called")


def _btn_show_theme():
    theme = vx.ui.get_theme()
    _log(f"vx.ui.get_theme() → {len(theme)} key(s)")
    lines = "\n".join(f"  {k}: {v}" for k, v in sorted(theme.items()))
    messagebox.showinfo("Current Theme", lines, parent=_win)


def _btn_version():
    ver = vx.version.get()
    _log(f"vx.version.get() → {ver!r}")
    messagebox.showinfo("V0RTEX Version", f"Running version: {ver}", parent=_win)


def _btn_last_result():
    res = vx.scan.get_last_result()
    if res:
        _log(f"vx.scan.get_last_result() → file={res.get('file', '?')}")
        messagebox.showinfo("Last Scan Result", str(res)[:600], parent=_win)
    else:
        _log("vx.scan.get_last_result() → None (no scan yet)")
        messagebox.showinfo("Last Scan Result", "No scan performed yet.", parent=_win)


def _btn_history():
    hist = vx.scan.get_history(5)
    _log(f"vx.scan.get_history(5) → {len(hist) if hist else 0} record(s)")
    if hist:
        summary = "\n".join(str(r.get("file", "?")) for r in hist)
        messagebox.showinfo("Scan History (last 5)", summary, parent=_win)
    else:
        messagebox.showinfo("Scan History", "No scan history available.", parent=_win)


def _btn_ioc():
    iocs = vx.ioc.get_last_extracted()
    fname = iocs.get("file", "") if isinstance(iocs, dict) else ""
    total = sum(len(v) for k, v in iocs.items() if isinstance(v, list)) if isinstance(iocs, dict) else 0
    _log(f"vx.ioc.get_last_extracted() → {total} IOC(s) from '{fname}'")
    if isinstance(iocs, dict) and total > 0:
        lines = [f"File: {fname}", ""]
        for key in ("ips", "domains", "urls", "emails", "registry"):
            vals = iocs.get(key, [])
            if vals:
                lines.append(f"[{key.upper()}] ({len(vals)})")
                lines.extend(f"  {v}" for v in vals[:10])
                if len(vals) > 10:
                    lines.append(f"  ... +{len(vals)-10} more")
        susp = iocs.get("susp_apis", {})
        if susp:
            lines.append(f"[SUSPICIOUS APIs] ({len(susp)} categories)")
            for cat, apis in susp.items():
                lines.append(f"  {cat}: {', '.join(apis[:5])}")
        messagebox.showinfo("Last IOCs", "\n".join(lines), parent=_win)
    else:
        messagebox.showinfo("Last IOCs", "No IOCs extracted yet. Run a scan first.", parent=_win)


def _btn_notes():
    vx.notes.append("[TestPlugin] Note appended via vx.notes.append() — test OK")
    _log("vx.notes.append() called — note added to scratchpad")
    messagebox.showinfo("Notes", "Note appended to V0RTEX scratchpad.", parent=_win)


def _btn_fs_read_external():
    path = filedialog.askopenfilename(title="Pick a file to read via vx.fs.read_external()", parent=_win)
    if not path:
        _log("vx.fs.read_external() — cancelled by user")
        return
    try:
        data = vx.fs.read_external(path)
        size = len(data)
        _log(f"vx.fs.read_external({path!r}) → {size} bytes")
        preview = data[:400]
        try:
            preview_str = preview.decode("utf-8", errors="replace")
        except Exception:
            preview_str = repr(preview)
        messagebox.showinfo(
            "fs.read_external",
            f"Path: {path}\nSize: {size} bytes\n\nPreview (first 400 bytes):\n{preview_str}",
            parent=_win,
        )
    except Exception as e:
        _log(f"vx.fs.read_external() ERROR: {e}")
        messagebox.showerror("fs.read_external failed", str(e), parent=_win)


def _btn_fs_write(fmt):
    sample_data = {
        "json": '{"test": true, "plugin": "V0RTEX Test Plugin", "fmt": "json"}',
        "csv":  "name,value,ok\ntest_plugin,1,true\nfmt_csv,2,true\n",
        "xml":  '<?xml version="1.0"?><test><plugin>V0RTEX Test Plugin</plugin><fmt>xml</fmt></test>',
        "html": "<html><body><h1>V0RTEX Test Plugin</h1><p>fmt: html</p></body></html>",
        "pdf":  b"%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n",
        "zip":  None,
    }
    if fmt == "zip":
        import io, zipfile
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("test.txt", "V0RTEX Test Plugin — zip write test\n")
        data = buf.getvalue()
    elif fmt == "pdf":
        data = sample_data["pdf"]
    else:
        data = sample_data[fmt]
    try:
        dest = vx.fs.write_file(f"testfile_{fmt}", data, fmt)
        _log(f"vx.fs.write_file('testfile_{fmt}', data, {fmt!r}) → {dest}")
        messagebox.showinfo("fs.write_file", f"Written to:\n{dest}", parent=_win)
    except Exception as e:
        _log(f"vx.fs.write_file({fmt!r}) ERROR: {e}")
        messagebox.showerror("fs.write_file failed", str(e), parent=_win)


def _btn_fs_read_logs():
    try:
        logs = vx.fs.read_logs()
        count = len(logs)
        total_bytes = sum(len(v) for v in logs.values())
        _log(f"vx.fs.read_logs() → {count} file(s), {total_bytes} total chars")
        if logs:
            summary = "\n".join(f"  {k}: {len(v)} chars" for k, v in sorted(logs.items()))
            messagebox.showinfo("fs.read_logs", f"{count} log file(s):\n\n{summary}", parent=_win)
        else:
            messagebox.showinfo("fs.read_logs", "No log files found in debug_log/.", parent=_win)
    except Exception as e:
        _log(f"vx.fs.read_logs() ERROR: {e}")
        messagebox.showerror("fs.read_logs failed", str(e), parent=_win)


def _btn_fs_read_reports():
    try:
        reports = vx.fs.read_reports()
        count = len(reports)
        total_bytes = sum(len(v) for v in reports.values())
        _log(f"vx.fs.read_reports() → {count} file(s), {total_bytes} total chars")
        if reports:
            summary = "\n".join(f"  {k}: {len(v)} chars" for k, v in sorted(reports.items())[:20])
            messagebox.showinfo("fs.read_reports", f"{count} report file(s):\n\n{summary}", parent=_win)
        else:
            messagebox.showinfo("fs.read_reports", "No report files found in reports/.", parent=_win)
    except Exception as e:
        _log(f"vx.fs.read_reports() ERROR: {e}")
        messagebox.showerror("fs.read_reports failed", str(e), parent=_win)


def _btn_net_bg_request():
    url = "https://httpbin.org/get"
    _log(f"vx.net.background_request('GET', {url!r}) — firing in background thread…")
    result_box = vx.net.background_request("GET", url, timeout=10)

    def _poll(start):
        if result_box[0] is None:
            if time.time() - start > 12:
                _log("vx.net.background_request() — timed out waiting for result")
                return
            _win.after(300, lambda: _poll(start))
            return
        r = result_box[0]
        if "error" in r:
            _log(f"vx.net.background_request() ERROR: {r['error']}")
            messagebox.showerror("net.background_request failed", r["error"], parent=_win)
        else:
            body_preview = r.get("body", b"")[:300]
            try:
                body_str = body_preview.decode("utf-8", errors="replace")
            except Exception:
                body_str = repr(body_preview)
            _log(f"vx.net.background_request() → status={r.get('status')}, body={len(r.get('body', b''))} bytes")
            messagebox.showinfo(
                "net.background_request",
                f"Status: {r.get('status')}\nBody preview:\n{body_str}",
                parent=_win,
            )

    _win.after(300, lambda: _poll(time.time()))


def _btn_net_listen():
    global _srv_socket
    if _srv_socket is not None:
        _log("vx.net.listen() — listener already running on :19876")
        messagebox.showinfo("net.listen", "Listener already running on 127.0.0.1:19876.", parent=_win)
        return

    def _handler(conn, addr):
        _log(f"vx.net.listen() — connection from {addr}")
        try:
            conn.sendall(b"V0RTEX Test Plugin - listener OK\r\n")
            conn.close()
        except Exception:
            pass

    try:
        _srv_socket = vx.net.listen("127.0.0.1", 19876, _handler)
        _log("vx.net.listen('127.0.0.1', 19876, handler) → socket open")
        messagebox.showinfo("net.listen", "Listener started on 127.0.0.1:19876.\nConnect with: telnet 127.0.0.1 19876", parent=_win)
    except Exception as e:
        _log(f"vx.net.listen() ERROR: {e}")
        messagebox.showerror("net.listen failed", str(e), parent=_win)


def _btn_net_listen_stop():
    global _srv_socket
    if _srv_socket is None:
        _log("vx.net.listen() — no listener running")
        messagebox.showinfo("net.listen", "No listener is currently running.", parent=_win)
        return
    try:
        _srv_socket.close()
        _log("net.listen socket closed manually")
        messagebox.showinfo("net.listen", "Listener closed.", parent=_win)
    except Exception as e:
        _log(f"net.listen close ERROR: {e}")
    _srv_socket = None


def _btn_proc_list():
    try:
        procs = vx.proc.list_processes()
        count = len(procs) if procs else 0
        _log(f"vx.proc.list_processes() → {count} process(es)")
        if procs:
            lines = []
            for p in procs[:30]:
                if "cmd" in p:
                    lines.append(f"  PID {p.get('pid','?')}  {p.get('cmd','?')[:60]}")
                else:
                    lines.append(f"  PID {p.get('pid','?')}  {p.get('name','?')}  {p.get('mem','')}")
            if count > 30:
                lines.append(f"  ... +{count - 30} more")
            messagebox.showinfo(f"proc.list_processes ({count})", "\n".join(lines), parent=_win)
        else:
            messagebox.showinfo("proc.list_processes", "No processes returned.", parent=_win)
    except Exception as e:
        _log(f"vx.proc.list_processes() ERROR: {e}")
        messagebox.showerror("proc.list_processes failed", str(e), parent=_win)


def _btn_sys_registry():
    import sys as _sys
    if _sys.platform != "win32":
        _log("vx.sys.read_registry() — skipped (not Windows)")
        messagebox.showinfo("sys.read_registry", "sys.read.registry is Windows only — skipped on this platform.", parent=_win)
        return
    key = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"
    try:
        result = vx.sys.read_registry(key)
        count = len(result) if isinstance(result, dict) else 0
        _log(f"vx.sys.read_registry({key!r}) → {count} value(s)")
        if isinstance(result, dict):
            lines = []
            for k, v in list(result.items())[:20]:
                val_str = str(v.get("value", ""))[:60] if isinstance(v, dict) else str(v)[:60]
                lines.append(f"  {k}: {val_str}")
            if count > 20:
                lines.append(f"  ... +{count - 20} more")
            messagebox.showinfo(f"sys.read_registry ({count} values)", "\n".join(lines), parent=_win)
        else:
            messagebox.showinfo("sys.read_registry", str(result), parent=_win)
    except Exception as e:
        _log(f"vx.sys.read_registry() ERROR: {e}")
        messagebox.showerror("sys.read_registry failed", str(e), parent=_win)


def _btn_sys_env():
    try:
        env = vx.sys.read_env()
        count = len(env)
        _log(f"vx.sys.read_env() → {count} variable(s)")
        safe_keys = ["OS", "COMPUTERNAME", "USERNAME", "PROCESSOR_ARCHITECTURE",
                     "PROCESSOR_IDENTIFIER", "NUMBER_OF_PROCESSORS",
                     "SystemRoot", "TEMP", "TMP", "PATHEXT", "HOMEDRIVE",
                     "SHELL", "TERM", "LANG", "HOME", "USER", "LOGNAME", "PWD"]
        lines = []
        for k in safe_keys:
            if k in env:
                lines.append(f"  {k}={env[k][:80]}")
        lines.append(f"\n  (showing {len(lines)} of {count} total variables)")
        messagebox.showinfo("sys.read_env", "\n".join(lines), parent=_win)
    except Exception as e:
        _log(f"vx.sys.read_env() ERROR: {e}")
        messagebox.showerror("sys.read_env failed", str(e), parent=_win)


def _clear_log():
    global _log_lines
    _log_lines.clear()
    if _win and _win.winfo_exists():
        try:
            _txt.config(state="normal")
            _txt.delete("1.0", "end")
            _txt.config(state="disabled")
        except Exception:
            pass
