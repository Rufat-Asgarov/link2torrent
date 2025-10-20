#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
link_to_torrent_gui.py — Make a .torrent from a direct download link, with a simple GUI.

Requires: requests  (pip install requests)

Features:
- Paste an HTTP/HTTPS URL, choose a folder, click "Create .torrent".
- Optional: trackers (announce list), private flag, custom name, piece length, comment.
- Adds the original URL as a web seed (BEP-19) to accelerate downloads via HTTP.
- Progress bar (if server returns Content-Length), otherwise indeterminate.
- Responsive UI (hashing/downloading runs in a background thread).

Note:
- This creates a single-file torrent (BitTorrent v1).
"""

import argparse
import hashlib
import os
import re
import sys
import time
import threading
from urllib.parse import urlparse, unquote

# ---- third-party ----
try:
    import requests
except ImportError:
    raise SystemExit("This app requires the 'requests' package.\nInstall with: pip install requests")

# ---- stdlib GUI ----
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

# =======================
# Minimal bencode writer
# =======================
def bencode_int(i: int) -> bytes:
    return b"i" + str(i).encode() + b"e"

def bencode_bytes(b: bytes) -> bytes:
    return str(len(b)).encode() + b":" + b

def bencode_str(s: str) -> bytes:
    return bencode_bytes(s.encode())

def bencode_list(lst) -> bytes:
    out = [b"l"]
    for v in lst:
        out.append(bencode(v))
    out.append(b"e")
    return b"".join(out)

def bencode_dict(d: dict) -> bytes:
    # Keys must be sorted lexicographically by raw bytes
    def _kbytes(k):
        return k.encode() if isinstance(k, str) else k
    out = [b"d"]
    for k in sorted(d.keys(), key=_kbytes):
        kb = _kbytes(k)
        out.append(bencode_bytes(kb))
        out.append(bencode(d[k]))
    out.append(b"e")
    return b"".join(out)

def bencode(v) -> bytes:
    if isinstance(v, int):
        return bencode_int(v)
    if isinstance(v, bytes):
        return bencode_bytes(v)
    if isinstance(v, str):
        return bencode_str(v)
    if isinstance(v, list):
        return bencode_list(v)
    if isinstance(v, dict):
        return bencode_dict(v)
    raise TypeError(f"Unsupported type for bencode: {type(v)}")

# =======================
# Helpers
# =======================
def parse_piece_length(s: str | None, total_size: int | None) -> int:
    """
    Accepts: 262144, '256KiB', '1MiB', '4MB'.
    Heuristic default if not provided: <=2GB: 256KiB; <=8GB: 512KiB; else 1MiB.
    """
    if s:
        m = re.fullmatch(r"(?i)\s*(\d+)\s*([kmgt]?i?b?)?\s*", s.strip())
        if not m:
            raise ValueError(f"Invalid piece length: {s}")
        n = int(m.group(1))
        unit = (m.group(2) or "").lower()
        mult = 1
        if unit in ("k", "kb"): mult = 1000
        elif unit in ("ki", "kib"): mult = 1024
        elif unit in ("m", "mb"): mult = 1000**2
        elif unit in ("mi", "mib"): mult = 1024**2
        elif unit in ("g", "gb"): mult = 1000**3
        elif unit in ("gi", "gib"): mult = 1024**3
        return n * mult
    if total_size is None:
        return 256 * 1024
    if total_size <= 2 * 1024**3:
        return 256 * 1024
    if total_size <= 8 * 1024**3:
        return 512 * 1024
    return 1024 * 1024

def filename_from_url(url: str) -> str:
    path = urlparse(url).path
    if not path or path.endswith("/"):
        return "downloaded.file"
    name = os.path.basename(path)
    return unquote(name) or "downloaded.file"

def filename_from_content_disposition(cd: str | None) -> str | None:
    if not cd:
        return None
    # RFC 5987 / filename*
    m = re.search(r'filename\*=\s*([^\'"]+)\'[^\']*\'([^;]+)', cd, flags=re.I)
    if m:
        try:
            return unquote(m.group(2).strip().strip('"'))
        except Exception:
            pass
    # Simple filename=
    m = re.search(r'filename\s*=\s*"([^"]+)"', cd, flags=re.I)
    if m:
        return m.group(1)
    m = re.search(r'filename\s*=\s*([^;]+)', cd, flags=re.I)
    if m:
        return m.group(1).strip().strip('"')
    return None

def head_content_info(url: str, user_agent: str | None = None):
    """
    Try HEAD, fall back to GET, to get name and length.
    """
    headers = {}
    if user_agent:
        headers["User-Agent"] = user_agent

    def _try(method):
        try:
            return requests.request(method, url, allow_redirects=True, timeout=20, headers=headers)
        except requests.RequestException:
            return None

    resp = _try("HEAD") or _try("GET")
    if not resp:
        return None, None, None, {}
    cd = resp.headers.get("Content-Disposition")
    cl = resp.headers.get("Content-Length")
    mime = resp.headers.get("Content-Type")
    name = filename_from_content_disposition(cd) or filename_from_url(resp.url)
    size = int(cl) if cl and cl.isdigit() else None
    return name, size, mime, headers

def stream_hash_pieces(url: str, piece_length: int, headers: dict | None, progress_cb=None):
    """
    Streams the content once and returns (pieces_concat, total_length).
    Calls progress_cb(bytes_done, total_bytes|None) if provided.
    """
    done = 0
    with requests.get(url, stream=True, headers=headers or {}, timeout=30) as r:
        r.raise_for_status()
        total = r.headers.get("Content-Length")
        total_int = int(total) if total and total.isdigit() else None
        buf = bytearray()
        pieces = []
        for chunk in r.iter_content(chunk_size=64 * 1024):
            if not chunk:
                continue
            view = memoryview(chunk)
            while view:
                need = piece_length - len(buf)
                take = min(need, len(view))
                buf.extend(view[:take])
                view = view[take:]
                done += take
                if progress_cb:
                    progress_cb(done, total_int)
                if len(buf) == piece_length:
                    pieces.append(hashlib.sha1(buf).digest())
                    buf.clear()
        if buf:
            pieces.append(hashlib.sha1(buf).digest())
        return b"".join(pieces), done

def build_torrent_from_url(
    url: str,
    out_path: str,
    name_override: str | None = None,
    announce_csv: str | None = None,
    private: bool = False,
    comment: str | None = None,
    piece_length_str: str | None = None,
    user_agent: str | None = None,
    progress_cb=None,
):
    filename, content_len, _mime, head_headers = head_content_info(url, user_agent=user_agent)
    if name_override:
        filename = name_override
    if not filename:
        filename = filename_from_url(url)

    headers = {}
    if user_agent:
        headers["User-Agent"] = user_agent
    elif head_headers:
        headers.update(head_headers)

    piece_length = parse_piece_length(piece_length_str, content_len)

    pieces_concat, total_len = stream_hash_pieces(url, piece_length, headers=headers, progress_cb=progress_cb)

    info = {
        "name": filename,
        "length": total_len,
        "piece length": piece_length,
        "pieces": pieces_concat,
    }
    if private:
        info["private"] = 1

    torrent = {
        "info": info,
        "creation date": int(time.time()),
        "created by": "link_to_torrent_gui.py",
        "url-list": url,  # web seed
    }
    if comment:
        torrent["comment"] = comment

    if announce_csv:
        trackers = [t.strip() for t in announce_csv.split(",") if t.strip()]
        if trackers:
            torrent["announce"] = trackers[0]
            if len(trackers) > 1:
                torrent["announce-list"] = [[t] for t in trackers]

    # Ensure folder exists
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "wb") as f:
        f.write(bencode_dict(torrent))

    return {
        "output": out_path,
        "name": filename,
        "size": total_len,
        "piece_length": piece_length,
        "num_pieces": len(pieces_concat) // 20,
    }

# =======================
# GUI
# =======================
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Link → .torrent")
        self.geometry("640x420")
        self.minsize(600, 420)

        self.var_url = tk.StringVar()
        self.var_folder = tk.StringVar()
        self.var_name = tk.StringVar()
        self.var_announce = tk.StringVar()
        self.var_piece = tk.StringVar()  # e.g., 256KiB, 1MiB
        self.var_comment = tk.StringVar()
        self.var_useragent = tk.StringVar()
        self.var_private = tk.BooleanVar(value=False)

        self._build_widgets()
        self.worker = None
        self.stop_flag = False

    def _build_widgets(self):
        pad = {"padx": 10, "pady": 6}

        frm = ttk.Frame(self)
        frm.pack(fill="both", expand=True)

        # URL
        ttk.Label(frm, text="Direct download URL:").grid(row=0, column=0, sticky="w", **pad)
        url_entry = ttk.Entry(frm, textvariable=self.var_url)
        url_entry.grid(row=0, column=1, columnspan=2, sticky="ew", **pad)

        # Folder
        ttk.Label(frm, text="Save folder:").grid(row=1, column=0, sticky="w", **pad)
        folder_entry = ttk.Entry(frm, textvariable=self.var_folder)
        folder_entry.grid(row=1, column=1, sticky="ew", **pad)
        ttk.Button(frm, text="Browse…", command=self.on_browse).grid(row=1, column=2, sticky="e", **pad)

        # Optional fields: name, trackers, piece length
        ttk.Label(frm, text="(Optional) Name in torrent:").grid(row=2, column=0, sticky="w", **pad)
        name_entry = ttk.Entry(frm, textvariable=self.var_name)
        name_entry.grid(row=2, column=1, columnspan=2, sticky="ew", **pad)

        ttk.Label(frm, text="(Optional) Trackers (comma-separated):").grid(row=3, column=0, sticky="w", **pad)
        ann_entry = ttk.Entry(frm, textvariable=self.var_announce)
        ann_entry.grid(row=3, column=1, columnspan=2, sticky="ew", **pad)

        ttk.Label(frm, text="(Optional) Piece length:").grid(row=4, column=0, sticky="w", **pad)
        piece_entry = ttk.Entry(frm, textvariable=self.var_piece)
        piece_entry.grid(row=4, column=1, sticky="ew", **pad)
        ttk.Label(frm, text="e.g. 256KiB, 1MiB").grid(row=4, column=2, sticky="w", **pad)

        ttk.Label(frm, text="(Optional) Comment:").grid(row=5, column=0, sticky="w", **pad)
        comment_entry = ttk.Entry(frm, textvariable=self.var_comment)
        comment_entry.grid(row=5, column=1, columnspan=2, sticky="ew", **pad)

        ttk.Label(frm, text="(Optional) User-Agent:").grid(row=6, column=0, sticky="w", **pad)
        ua_entry = ttk.Entry(frm, textvariable=self.var_useragent)
        ua_entry.grid(row=6, column=1, columnspan=2, sticky="ew", **pad)

        # Private flag
        private_chk = ttk.Checkbutton(frm, text="Private (disable DHT/PEX)", variable=self.var_private)
        private_chk.grid(row=7, column=0, columnspan=3, sticky="w", **pad)

        # Progress
        ttk.Separator(frm).grid(row=8, column=0, columnspan=3, sticky="ew", pady=(8, 2))
        self.progress = ttk.Progressbar(frm, mode="determinate", maximum=100)
        self.progress.grid(row=9, column=0, columnspan=3, sticky="ew", **pad)
        self.progress_label = ttk.Label(frm, text="Idle")
        self.progress_label.grid(row=10, column=0, columnspan=3, sticky="w", **pad)

        # Buttons
        btn_frame = ttk.Frame(frm)
        btn_frame.grid(row=11, column=0, columnspan=3, sticky="e", **pad)
        self.btn_create = ttk.Button(btn_frame, text="Create .torrent", command=self.on_create)
        self.btn_create.pack(side="left", padx=6)
        self.btn_cancel = ttk.Button(btn_frame, text="Cancel", command=self.on_cancel, state="disabled")
        self.btn_cancel.pack(side="left", padx=6)

        # grid config
        frm.columnconfigure(1, weight=1)

    def on_browse(self):
        folder = filedialog.askdirectory(title="Choose folder to save .torrent")
        if folder:
            self.var_folder.set(folder)

    def set_busy(self, busy: bool):
        self.btn_create.config(state="disabled" if busy else "normal")
        self.btn_cancel.config(state="normal" if busy else "disabled")
        if busy:
            self.progress_label.config(text="Starting…")
        else:
            self.progress_label.config(text="Idle")

    def on_cancel(self):
        # We can't easily stop requests mid-stream gracefully; mark a flag
        # and let the worker exit ASAP (the next progress tick will raise).
        self.stop_flag = True
        self.progress_label.config(text="Canceling…")

    # Progress callback passed into hashing function
    def _progress_cb(self, done: int, total: int | None):
        if self.stop_flag:
            raise RuntimeError("Operation canceled by user")

        if total and total > 0:
            pct = max(0, min(100, int(done * 100 / total)))
            self.progress.config(mode="determinate", value=pct)
            # Human readable
            self.progress_label.config(text=f"Downloading & hashing… {pct}% ({done}/{total} bytes)")
        else:
            # Unknown size
            self.progress.config(mode="indeterminate")
            if not str(self.progress["mode"]) == "indeterminate":
                self.progress.config(mode="indeterminate")
            self.progress.start(80)
            self.progress_label.config(text=f"Downloading & hashing… {done} bytes")

        # Force UI update safely
        self.update_idletasks()

    def on_create(self):
        url = self.var_url.get().strip()
        folder = self.var_folder.get().strip()
        name = self.var_name.get().strip() or None
        announce = self.var_announce.get().strip() or None
        piece_len = self.var_piece.get().strip() or None
        comment = self.var_comment.get().strip() or None
        ua = self.var_useragent.get().strip() or None
        is_private = bool(self.var_private.get())

        if not url:
            messagebox.showerror("Missing URL", "Please paste a direct download URL.")
            return
        if not folder:
            messagebox.showerror("Missing folder", "Please choose a folder to save the .torrent.")
            return
        if not os.path.isdir(folder):
            messagebox.showerror("Invalid folder", "The selected folder does not exist.")
            return

        # Output path: infer filename now to show user where it will go
        try:
            inferred_name, _, _, _ = head_content_info(url, user_agent=ua)
        except Exception:
            inferred_name = None
        if not inferred_name:
            inferred_name = filename_from_url(url)
        if name:
            inferred_name = name
        torrent_filename = inferred_name + ".torrent"
        out_path = os.path.join(folder, torrent_filename)

        # Confirm overwrite
        if os.path.exists(out_path):
            if not messagebox.askyesno("Overwrite?", f"{torrent_filename} already exists.\nOverwrite?"):
                return

        # Run worker
        self.stop_flag = False
        self.set_busy(True)

        def worker():
            try:
                result = build_torrent_from_url(
                    url=url,
                    out_path=out_path,
                    name_override=name,
                    announce_csv=announce,
                    private=is_private,
                    comment=comment,
                    piece_length_str=piece_len,
                    user_agent=ua,
                    progress_cb=self._progress_cb,
                )
            except Exception as e:
                # Switch back to UI thread to show the error
                self.after(0, self._on_done, None, e, out_path)
                return
            self.after(0, self._on_done, result, None, out_path)

        self.worker = threading.Thread(target=worker, daemon=True)
        self.worker.start()

    def _on_done(self, result, error, out_path):
        # Stop indeterminate bar if active
        try:
            self.progress.stop()
        except Exception:
            pass
        self.set_busy(False)

        if error:
            if isinstance(error, RuntimeError) and "canceled" in str(error).lower():
                self.progress_label.config(text="Canceled.")
                return
            messagebox.showerror("Error", f"Failed to create torrent:\n{error}")
            self.progress_label.config(text="Failed.")
            return

        self.progress.config(value=100, mode="determinate")
        self.progress_label.config(text="Done.")
        details = (
            f"Created:\n{out_path}\n\n"
            f"Name: {result['name']}\n"
            f"Size: {result['size']} bytes\n"
            f"Piece length: {result['piece_length']} bytes\n"
            f"Pieces: {result['num_pieces']}\n"
        )
        messagebox.showinfo("Success", details)

def main():
    # Allow optional CLI for power users; otherwise just launch GUI
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--no-gui", action="store_true",
                        help="Run without GUI (for scripting).")
    parser.add_argument("--url")
    parser.add_argument("--out")
    parser.add_argument("--name")
    parser.add_argument("--announce")
    parser.add_argument("--private", action="store_true")
    parser.add_argument("--comment")
    parser.add_argument("--piece-length")
    parser.add_argument("--user-agent")
    args, _ = parser.parse_known_args()

    if args.no_gui:
        if not args.url or not args.out:
            print("Usage (no GUI): --no-gui --url URL --out /path/to/file.torrent [--name ... --announce ... --private --comment ... --piece-length ... --user-agent ...]")
            sys.exit(2)
        result = build_torrent_from_url(
            url=args.url,
            out_path=args.out,
            name_override=args.name,
            announce_csv=args.announce,
            private=bool(args.private),
            comment=args.comment,
            piece_length_str=args.piece_length,
            user_agent=args.user_agent,
        )
        print("Torrent created:", result)
        return

    app = App()
    app.mainloop()

if __name__ == "__main__":
    main()
