# V0RTEX Plugin
# Name: V0RTEX Test Plugin
# Version: 1.0.0
# Author: Vider_06
# Description: Developer test plugin — exercises every lifecycle hook and Verified API call
# Dependencies: none
# Class: Verified
# Elevated-Permissions: none
# Background-Network: no
# Background-Endpoints: none
# Min-V0RTEX-Version: 1.0.1

import tkinter as tk
from tkinter import ttk, messagebox
import threading
import time

_win        = None
_log_lines  = []
_scan_cb_id = None


def _log(msg):
    ts = time.strftime("%H:%M:%S")
    _log_lines.append(f"[{ts}] {msg}")
    if _win and _win.winfo_exists():
        try:
            _txt.config(state="normal")
            _txt.insert("end", f"[{ts}] {msg}\n")
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
    global _win
    _log("on_unload() called — cleaning up")
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

    theme = vx.ui.get_theme()
    bg      = theme.get("bg",      "#1e1e2e")
    surface = theme.get("surface", "#313244")
    fg      = theme.get("fg",      "#cdd6f4")
    accent  = theme.get("accent",  "#89b4fa")
    green   = theme.get("green",   "#a6e3a1")
    red     = theme.get("red",     "#f38ba8")
    yellow  = theme.get("yellow",  "#f9e2af")
    font_ui = theme.get("font",    "Consolas")

    _win = tk.Toplevel(root)
    _win.title("V0RTEX Test Plugin — API & Lifecycle Tester")
    _win.configure(bg=bg)
    _win.resizable(True, True)
    _win.geometry("780x560")
    _win.minsize(640, 420)

    def _mkbtn(parent, label, cmd, color):
        b = tk.Button(
            parent, text=label, command=cmd,
            bg=color, fg=bg, font=(font_ui, 9, "bold"),
            relief="flat", bd=0, padx=10, pady=6, cursor="hand2",
            activebackground=fg, activeforeground=bg,
        )
        b.pack(side="left", padx=4, pady=4)
        return b

    hdr = tk.Frame(_win, bg=surface)
    hdr.pack(fill="x", padx=0, pady=0)
    tk.Label(
        hdr,
        text="  🧪  V0RTEX Test Plugin  —  Verified API & Lifecycle Tester",
        bg=surface, fg=accent,
        font=(font_ui, 11, "bold"), anchor="w",
    ).pack(side="left", padx=8, pady=8)
    tk.Label(
        hdr, text="v1.0.0", bg=surface, fg=yellow,
        font=(font_ui, 9),
    ).pack(side="right", padx=12, pady=8)

    body = tk.Frame(_win, bg=bg)
    body.pack(fill="both", expand=True, padx=10, pady=8)

    left = tk.Frame(body, bg=bg)
    left.pack(side="left", fill="y", padx=(0, 8))

    def _section(parent, title):
        f = tk.LabelFrame(
            parent, text=title,
            bg=bg, fg=accent,
            font=(font_ui, 9, "bold"),
            relief="groove", bd=1,
        )
        f.pack(fill="x", pady=(0, 8))
        return f

    sec_ui = _section(left, "vx.ui — UI API")
    _mkbtn(sec_ui, "notify info",    lambda: _btn_notify("info"),    green)
    _mkbtn(sec_ui, "notify warning", lambda: _btn_notify("warning"), yellow)
    _mkbtn(sec_ui, "notify error",   lambda: _btn_notify("error"),   red)

    sec_theme = _section(left, "vx.ui.get_theme()")
    _mkbtn(sec_theme, "Show Theme", _btn_show_theme, accent)

    sec_ver = _section(left, "vx.version.get()")
    _mkbtn(sec_ver, "Get V0RTEX Version", _btn_version, accent)

    sec_scan = _section(left, "vx.scan")
    _mkbtn(sec_scan, "last result",  _btn_last_result, green)
    _mkbtn(sec_scan, "get history",  _btn_history,     accent)

    sec_ioc = _section(left, "vx.ioc")
    _mkbtn(sec_ioc, "last IOCs", _btn_ioc, accent)

    sec_notes = _section(left, "vx.notes")
    _mkbtn(sec_notes, "Append note", _btn_notes, green)

    sec_lc = _section(left, "Lifecycle")
    _mkbtn(sec_lc, "simulate on_update", lambda: on_update("1.0.0", "1.0.1"), yellow)
    _mkbtn(sec_lc, "clear log", _clear_log, red)

    right = tk.Frame(body, bg=bg)
    right.pack(side="left", fill="both", expand=True)

    tk.Label(
        right, text="Event Log", bg=bg, fg=accent,
        font=(font_ui, 9, "bold"), anchor="w",
    ).pack(fill="x")

    log_frame = tk.Frame(right, bg=surface, bd=1, relief="sunken")
    log_frame.pack(fill="both", expand=True)

    _txt = tk.Text(
        log_frame,
        bg=surface, fg=fg,
        font=(font_ui, 9),
        state="disabled", wrap="word",
        relief="flat", bd=0,
        selectbackground=accent, selectforeground=bg,
    )
    sb = ttk.Scrollbar(log_frame, command=_txt.yview)
    _txt.configure(yscrollcommand=sb.set)
    sb.pack(side="right", fill="y")
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
    _log(f"vx.ioc.get_last_extracted() → {len(iocs) if iocs else 0} IOC(s)")
    if iocs:
        messagebox.showinfo("Last IOCs", "\n".join(str(i) for i in list(iocs)[:20]), parent=_win)
    else:
        messagebox.showinfo("Last IOCs", "No IOCs extracted yet.", parent=_win)


def _btn_notes():
    vx.notes.append("[TestPlugin] Note appended via vx.notes.append() — test OK")
    _log("vx.notes.append() called — note added to scratchpad")
    messagebox.showinfo("Notes", "Note appended to V0RTEX scratchpad.", parent=_win)


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
