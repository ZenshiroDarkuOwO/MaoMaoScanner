import json
import queue
import sys
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

import customtkinter as ctk

from zen.rule_loader import load_rules
from zen.evtx_reader import read_events
from zen.scan_engine import scan_events
from zen.attack_coverage import coverage_report
from zen.live_monitor import LiveMonitor

BG          = "#090d13"
SIDEBAR     = "#0d1219"
CARD        = "#111823"
CARD_ALT    = "#0e141d"
ELEV        = "#182233"
BORDER      = "#222d3d"
TEXT        = "#e6edf3"
MUTED       = "#7d8aa0"
ACCENT      = "#2f81f7"
ACCENT_HOVER = "#4c94ff"
VIOLET      = "#a371f7"
CYAN        = "#39d0d8"
GREEN       = "#3fb950"
DANGER      = "#da3633"
CRITICAL    = "#ff5c57"
AMBER       = "#f7c948"

LEVELS = ["critical", "high", "medium", "low", "informational"]

LEVEL_COLORS = {
    "critical":      CRITICAL,
    "high":          "#ff9f43",
    "medium":        AMBER,
    "low":           "#58a6ff",
    "informational": "#8b949e",
}

LEVEL_ICONS = {
    "critical":      "🔴",
    "high":          "🟠",
    "medium":        "🟡",
    "low":           "🔵",
    "informational": "⚪",
}

LEVEL_LABELS = {
    "critical": "Critical", "high": "High", "medium": "Medium",
    "low": "Low", "informational": "Info",
}

SEVERITY_ORDER = {
    "critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4
}

FONT = "Segoe UI"
MONO = "Consolas"

def set_taskbar_icon():
    
    try:
        import ctypes
        myappid = "ZenPCanalys.MaoMao.Edition.1"  
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(myappid)
    except Exception:
        pass

def get_base_path() -> Path:
    
    if getattr(sys, "frozen", False):
        return Path(sys._MEIPASS)
    return Path(__file__).parent.parent


def _mix(c1: str, c2: str, t: float) -> str:
    """ترکیب دو رنگ hex؛ t=0 → c1 ، t=1 → c2"""
    a = [int(c1[i:i + 2], 16) for i in (1, 3, 5)]
    b = [int(c2[i:i + 2], 16) for i in (1, 3, 5)]
    return "#%02x%02x%02x" % tuple(int(x * (1 - t) + y * t) for x, y in zip(a, b))


def _summarize(ev) -> str:
    if isinstance(ev, dict):
        parts = [f"{k}={v}" for k, v in ev.items() if k != "TimeCreated"]
        return "   ".join(parts)[:220]
    return str(ev)[:220]


class ZenApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self.title("MaoMaoScanner — 毛帽猫 Edition")
        self.geometry("1360x860")
        self.minsize(1100, 700)
        self.configure(fg_color=BG)

        self.report = None
        self.evtx_path = None
        self.batch_dir = None
        self.all_matches = []
        self.live_matches = []
        self.filter_level = "all"
        self.search_text = ""

        # Live monitor
        self.live_monitor = None
        self.live_active = False
        self.live_channel = tk.StringVar(value="System")

        # intern
        self._q = queue.Queue()
        self._scanning = False
        self._rows = {}
        self._row_counter = 0
        self._stat_vals = {}
        self._stat_tok = {}
        self._pulse_running = False
        self._pulse_state = False

        self._build_icon()
        self._build_layout()
        self._bind_shortcuts()
        self._update_coverage_card()
        self._refresh_chips()
        self._draw_bar()
        self._render_table()

        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.after(80, self._poll_queue)

    
    def _build_icon(self):
        
        try:
            from PIL import Image, ImageTk
            for candidate in (get_base_path() / "assets/cat.png", get_base_path() / "assets/cat.ico"):
                if candidate.exists():
                    pil_img = Image.open(candidate).convert("RGBA")
                    pil_img = pil_img.resize((32, 32), Image.LANCZOS)
                    self._icon = ImageTk.PhotoImage(pil_img)
                    self.iconphoto(True, self._icon)
                    break
        except Exception:
            pass

        
        self.after(200, self._set_taskbar_icon_win32)

    def _set_taskbar_icon_win32(self):
        
        try:
            import win32gui
            import win32con
            import win32api
            import os

            
            icon_path = None
            for candidate in (get_base_path() / "assets/cat.ico", get_base_path() / "assets/cat.png"):
                if candidate.exists():
                    icon_path = str(candidate.absolute())
                    break

            if not icon_path or not os.path.exists(icon_path):
                return

            
            hwnd = win32gui.GetParent(self.winfo_id())
            if not hwnd:
                hwnd = self.winfo_id()

            
            big_icon = win32gui.LoadImage(0, icon_path, win32con.IMAGE_ICON,
                                          32, 32, win32con.LR_LOADFROMFILE)
            small_icon = win32gui.LoadImage(0, icon_path, win32con.IMAGE_ICON,
                                            16, 16, win32con.LR_LOADFROMFILE)

            
            win32api.SendMessage(hwnd, win32con.WM_SETICON, win32con.ICON_BIG, big_icon)
            win32api.SendMessage(hwnd, win32con.WM_SETICON, win32con.ICON_SMALL, small_icon)
        except Exception:
            pass

    def _load_cat(self, size):
        try:
            from PIL import Image
            for candidate in (get_base_path() / "assets/cat.png", get_base_path() / "assets/cat.ico"):
                if candidate.exists():
                    return ctk.CTkImage(Image.open(candidate).convert("RGBA"), size=(size, size))
        except Exception:
            pass
        return None

    def _build_layout(self):
        self._build_statusbar()
        self._build_sidebar()
        self._build_main()

    # Status bar
    def _build_statusbar(self):
        bar = ctk.CTkFrame(self, fg_color=SIDEBAR, height=34, corner_radius=0)
        bar.pack(fill="x", side="bottom")
        bar.pack_propagate(False)

        self.status = ctk.CTkLabel(bar, text="● Bereit", anchor="w",
                                   font=ctk.CTkFont(family=FONT, size=11),
                                   text_color=MUTED)
        self.status.pack(side="left", padx=20)

        ctk.CTkLabel(bar, text="MaoMaoScanner v0.3.0",
                     font=ctk.CTkFont(family=FONT, size=11),
                     text_color=MUTED).pack(side="right", padx=20)

        self.progress = ctk.CTkProgressBar(bar, width=200, height=6,
                                           fg_color=BORDER, progress_color=ACCENT)
        self._statusbar = bar

    # Sidebar
    def _section(self, parent, text):
        ctk.CTkLabel(parent, text=text, anchor="w",
                     font=ctk.CTkFont(family=FONT, size=10, weight="bold"),
                     text_color=MUTED).pack(fill="x", padx=24, pady=(22, 6))

    def _side_btn(self, parent, text, command, primary=False):
        if primary:
            kw = dict(fg_color=ACCENT, hover_color=ACCENT_HOVER, text_color="white",
                      height=46, font=ctk.CTkFont(family=FONT, size=13, weight="bold"))
        else:
            kw = dict(fg_color="transparent", hover_color=ELEV, text_color=TEXT,
                      border_width=1, border_color=BORDER, height=38, anchor="w",
                      font=ctk.CTkFont(family=FONT, size=12))
        btn = ctk.CTkButton(parent, text=text, command=command, corner_radius=10, **kw)
        btn.pack(fill="x", padx=18, pady=3)
        return btn

    def _build_sidebar(self):
        side = ctk.CTkFrame(self, width=248, fg_color=SIDEBAR, corner_radius=0)
        side.pack(side="left", fill="y")
        side.pack_propagate(False)
        ctk.CTkFrame(self, width=1, fg_color=BORDER, corner_radius=0).pack(side="left", fill="y")

        # Brand
        brand = ctk.CTkFrame(side, fg_color="transparent")
        brand.pack(fill="x", padx=20, pady=(24, 0))

        cat_img = self._load_cat(54)
        if cat_img is not None:
            ctk.CTkLabel(brand, image=cat_img, text="").pack(side="left", padx=(0, 12))

        tb = ctk.CTkFrame(brand, fg_color="transparent")
        tb.pack(side="left")
        ctk.CTkLabel(tb, text="MaoMaoScanner", anchor="w",
                     font=ctk.CTkFont(family=FONT, size=18, weight="bold"),
                     text_color=TEXT).pack(anchor="w")
        ctk.CTkLabel(tb, text="毛帽猫   E D I T I O N", anchor="w",
                     font=ctk.CTkFont(family=FONT, size=8, weight="bold"),
                     text_color=VIOLET).pack(anchor="w")

        ctk.CTkLabel(side, text="Die Katze lässt das Log nicht aus",
                     font=ctk.CTkFont(family=FONT, size=11, slant="italic"),
                     text_color=MUTED, anchor="w", justify="left",
                     wraplength=200).pack(fill="x", padx=24, pady=(10, 0))

        # Quelle
        self._section(side, "QUELLE")
        self._side_btn(side, "📄   EVTX-Datei öffnen", self.load_file)
        self._side_btn(side, "📁   Ordner auswählen", self.load_batch_dir)

        # Analyse
        self._section(side, "ANALYSE")
        self.scan_btn = self._side_btn(side, "⚡   Scannen", self.scan, primary=True)

        # Live
        self._section(side, "ÜBERWACHUNG")
        ctk.CTkOptionMenu(side, values=["System", "Application", "Security"],
                          variable=self.live_channel,
                          fg_color=CARD, button_color=ELEV, button_hover_color=ACCENT,
                          dropdown_fg_color=CARD, dropdown_hover_color=ELEV,
                          dropdown_text_color=TEXT, text_color=TEXT,
                          height=34, corner_radius=8,
                          font=ctk.CTkFont(family=FONT, size=12)
                          ).pack(fill="x", padx=18, pady=(0, 4))
        self.live_btn = self._side_btn(side, "📡   Live Monitor", self.toggle_live_monitor)
        self.live_badge = ctk.CTkLabel(side, text="", anchor="w",
                                       font=ctk.CTkFont(family=FONT, size=11, weight="bold"),
                                       text_color=CRITICAL)
        self.live_badge.pack(fill="x", padx=24, pady=(4, 0))

        # Export
        self._section(side, "EXPORT")
        self._side_btn(side, "💾   JSON speichern", self.save_json)
        self._side_btn(side, "🌐   HTML Report", self.save_html)

        
        ctk.CTkLabel(side, text="F5 Scan  ·  Ctrl+O Öffnen  ·  Ctrl+F Suche",
                     font=ctk.CTkFont(family=FONT, size=9),
                     text_color=_mix(MUTED, SIDEBAR, 0.25)).pack(side="bottom", pady=(0, 16))

    def _build_main(self):
        main = ctk.CTkFrame(self, fg_color="transparent")
        main.pack(side="left", fill="both", expand=True, padx=26)

        
        pill = ctk.CTkFrame(main, fg_color=CARD, corner_radius=12,
                            border_width=1, border_color=BORDER, height=42)
        pill.pack(fill="x", pady=(22, 14))
        pill.pack_propagate(False)
        ctk.CTkLabel(pill, text="📂", font=ctk.CTkFont(size=14)).pack(side="left", padx=(14, 8))
        self.path_label = ctk.CTkLabel(pill, text="Keine Datei ausgewählt", anchor="w",
                                       text_color=MUTED,
                                       font=ctk.CTkFont(family=FONT, size=12))
        self.path_label.pack(side="left", fill="x", expand=True)

        
        stats = ctk.CTkFrame(main, fg_color="transparent")
        stats.pack(fill="x", pady=(0, 14))
        for i in range(5):
            stats.grid_columnconfigure(i, weight=1, uniform="stat")

        self.stat_events  = self._stat_card(stats, 0, "📜", "EREIGNISSE", "0", "#58a6ff")
        self.stat_matches = self._stat_card(stats, 1, "🎯", "TREFFER",    "0", CRITICAL)
        self.stat_rules   = self._stat_card(stats, 2, "🧩", "REGELN",     "0", AMBER)
        self.stat_crit    = self._stat_card(stats, 3, "🔥", "KRITISCH",   "0", "#ff7b72")
        self.stat_cov     = self._stat_card(stats, 4, "🛡", "ATT&CK",     "…", VIOLET)

        
        row = ctk.CTkFrame(main, fg_color="transparent")
        row.pack(fill="x", pady=(0, 8))

        self.chips = {}
        for key in ["all"] + LEVELS:
            btn = ctk.CTkButton(row, text=key, width=96 if key == "all" else 112, height=30,
                                corner_radius=15, fg_color="transparent",
                                hover_color=ELEV, border_width=1, border_color=BORDER,
                                text_color=MUTED,
                                font=ctk.CTkFont(family=FONT, size=11, weight="bold"),
                                command=lambda k=key: self._set_level(k))
            btn.pack(side="left", padx=(0, 6))
            self.chips[key] = btn

        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *a: self._apply_filter())
        self.search_entry = ctk.CTkEntry(row, textvariable=self.search_var, width=280,
                                         placeholder_text="🔍  Suchen (Regel, Ereignis)…",
                                         fg_color=CARD, border_color=BORDER, text_color=TEXT,
                                         height=32, corner_radius=16,
                                         font=ctk.CTkFont(family=FONT, size=12))
        self.search_entry.pack(side="right")
        self.search_entry.bind("<Escape>", lambda e: self.search_var.set(""))

        
        self.bar = tk.Canvas(main, height=6, bg=BG, highlightthickness=0, bd=0)
        self.bar.pack(fill="x", pady=(0, 12))
        self.bar.bind("<Configure>", lambda e: self._draw_bar())

        
        detail = ctk.CTkFrame(main, fg_color=CARD, corner_radius=14,
                              border_width=1, border_color=BORDER)
        detail.pack(side="bottom", fill="x", pady=(12, 18))

        dh = ctk.CTkFrame(detail, fg_color="transparent")
        dh.pack(fill="x", padx=16, pady=(10, 0))
        ctk.CTkLabel(dh, text="🔎  EREIGNIS-DETAILS", anchor="w",
                     font=ctk.CTkFont(family=FONT, size=10, weight="bold"),
                     text_color=MUTED).pack(side="left")
        ctk.CTkButton(dh, text="📋 Kopieren", width=96, height=24, corner_radius=8,
                      fg_color="transparent", hover_color=ELEV, text_color=MUTED,
                      border_width=1, border_color=BORDER,
                      font=ctk.CTkFont(family=FONT, size=10),
                      command=self._copy_detail).pack(side="right")

        self.detail = ctk.CTkTextbox(detail, height=120, fg_color=CARD_ALT,
                                     text_color=TEXT, corner_radius=10,
                                     font=ctk.CTkFont(family=MONO, size=11), wrap="word")
        self.detail.pack(fill="x", padx=12, pady=(8, 12))
        self.detail.tag_config("title", foreground=TEXT)
        self.detail.tag_config("meta", foreground=MUTED)
        for lvl, col in LEVEL_COLORS.items():
            self.detail.tag_config(f"lvl_{lvl}", foreground=col)
        self._set_detail_placeholder()

        
        table_frame = ctk.CTkFrame(main, fg_color=CARD, corner_radius=14,
                                   border_width=1, border_color=BORDER)
        table_frame.pack(fill="both", expand=True)

        style = ttk.Style()
        style.theme_use("clam")
        style.layout("Custom.Treeview", [("Treeview.treearea", {"sticky": "nswe"})])
        style.configure("Custom.Treeview",
                        background=CARD, fieldbackground=CARD, foreground=TEXT,
                        rowheight=32, borderwidth=0, relief="flat",
                        bordercolor=CARD, lightcolor=CARD, darkcolor=CARD,
                        font=(FONT, 10))
        style.configure("Custom.Treeview.Heading",
                        background=CARD_ALT, foreground=MUTED,
                        font=(FONT, 9, "bold"), relief="flat", borderwidth=0,
                        padding=(8, 9))
        style.map("Custom.Treeview.Heading", background=[("active", ELEV)])
        style.map("Custom.Treeview",
                  background=[("selected", "#1b3556")],
                  foreground=[("selected", "#ffffff")])

        columns = ("icon", "rule", "level", "event", "time", "details")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings",
                                 style="Custom.Treeview", selectmode="browse")
        headings = {"icon": "", "rule": "REGEL", "level": "SCHWERE",
                    "event": "EREIGNIS #", "time": "ZEIT", "details": "DETAILS"}
        widths = {"icon": 44, "rule": 270, "level": 100,
                  "event": 100, "time": 190, "details": 420}
        anchors = {"icon": "center", "rule": "w", "level": "center",
                   "event": "center", "time": "w", "details": "w"}
        for col in columns:
            self.tree.heading(col, text=headings[col], anchor=anchors[col])
            self.tree.column(col, width=widths[col], anchor=anchors[col],
                             stretch=(col in ("rule", "details")), minwidth=40)

        for level, color in LEVEL_COLORS.items():
            self.tree.tag_configure(level, foreground=color)
        self.tree.tag_configure("odd", background="#141c2a")
        self.tree.tag_configure("even", background=CARD)

        scrollbar = ctk.CTkScrollbar(table_frame, command=self.tree.yview,
                                     fg_color=CARD, button_color=BORDER,
                                     button_hover_color=ACCENT)
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.pack(side="left", fill="both", expand=True, padx=(10, 0), pady=10)
        scrollbar.pack(side="right", fill="y", padx=(0, 6), pady=10)

        self.tree.bind("<<TreeviewSelect>>", self._on_select)

        
        self.menu = tk.Menu(self, tearoff=0, bg=CARD, fg=TEXT, bd=0,
                            activebackground=ACCENT, activeforeground="white",
                            font=(FONT, 10))
        self.menu.add_command(label="Regelname kopieren", command=self._copy_rule)
        self.menu.add_command(label="Ereignis (JSON) kopieren", command=self._copy_event_json)
        self.menu.add_separator()
        self.menu.add_command(label="Nach dieser Regel filtern", command=self._filter_by_rule)
        for seq in ("<Button-3>", "<Button-2>"):
            self.tree.bind(seq, self._popup_menu)

        
        self.empty = ctk.CTkLabel(table_frame, text="", justify="center",
                                  font=ctk.CTkFont(family=FONT, size=13),
                                  text_color=MUTED, fg_color=CARD)

        
        self.count_label = ctk.CTkLabel(row, text="", text_color=MUTED,
                                        font=ctk.CTkFont(family=FONT, size=11))
        self.count_label.pack(side="right", padx=(0, 12))

    def _stat_card(self, parent, col, icon, title, value, color):
        card = ctk.CTkFrame(parent, fg_color=CARD, corner_radius=14,
                            border_width=1, border_color=BORDER)
        card.grid(row=0, column=col, sticky="nsew",
                  padx=(0 if col == 0 else 6, 0 if col == 4 else 6))

        chip = ctk.CTkFrame(card, width=46, height=46, corner_radius=12,
                            fg_color=_mix(color, CARD, 0.80))
        chip.pack(side="left", padx=(14, 12), pady=14)
        chip.pack_propagate(False)
        ctk.CTkLabel(chip, text=icon, font=ctk.CTkFont(size=19),
                     text_color=color).place(relx=0.5, rely=0.5, anchor="center")

        box = ctk.CTkFrame(card, fg_color="transparent")
        box.pack(side="left", fill="both", expand=True, pady=10)
        ctk.CTkLabel(box, text=title, anchor="w",
                     font=ctk.CTkFont(family=FONT, size=10, weight="bold"),
                     text_color=MUTED).pack(anchor="w")
        value_label = ctk.CTkLabel(box, text=value, anchor="w",
                                   font=ctk.CTkFont(family=FONT, size=26, weight="bold"),
                                   text_color=color)
        value_label.pack(anchor="w")
        return value_label

    def _bind_shortcuts(self):
        self.bind("<F5>", lambda e: self.scan())
        self.bind("<Control-o>", lambda e: self.load_file())
        self.bind("<Control-O>", lambda e: self.load_batch_dir())
        self.bind("<Control-f>", lambda e: self.search_entry.focus())

    
    def _status(self, text, color=MUTED):
        self.status.configure(text=text, text_color=color)

    def _set_stat(self, label, target):
        cur = self._stat_vals.get(label, 0)
        tok = self._stat_tok.get(label, 0) + 1
        self._stat_tok[label] = tok
        self._stat_vals[label] = target
        steps = 14

        def tick(i=1):
            if self._stat_tok.get(label) != tok:
                return
            v = target if i >= steps else int(cur + (target - cur) * i / steps)
            label.configure(text=f"{v:,}")
            if i < steps:
                self.after(18, lambda: tick(i + 1))

        tick()

    def _update_coverage_card(self):
        try:
            rules = load_rules(get_base_path() / "rules")
            cov = coverage_report(rules)
            self.stat_cov.configure(text=f"{len(cov['covered_techniques'])}")
        except Exception:
            pass

    def _combined(self):
        return self.live_matches + self.all_matches

    def _level_counts(self):
        counts = {lvl: 0 for lvl in LEVELS}
        for m in self._combined():
            lvl = m.get("level", "informational")
            counts[lvl if lvl in counts else "informational"] += 1
        return counts

    
    def _refresh_chips(self):
        counts = self._level_counts()
        total = sum(counts.values())
        for key, btn in self.chips.items():
            if key == "all":
                text, color = f"Alle  {total:,}", TEXT
            else:
                text = f"{LEVEL_ICONS[key]} {LEVEL_LABELS[key]}  {counts[key]:,}"
                color = LEVEL_COLORS[key]
            active = (self.filter_level == key)
            btn.configure(
                text=text,
                fg_color=_mix(color, BG, 0.82) if active else "transparent",
                border_color=color if active else BORDER,
                text_color=TEXT if active else MUTED,
            )

    def _draw_bar(self):
        c = self.bar
        c.delete("all")
        w = max(c.winfo_width(), 2)
        h = 6
        counts = self._level_counts()
        total = sum(counts.values())
        if total == 0:
            c.create_rectangle(0, 0, w, h, fill=BORDER, outline="")
            return
        x = 0
        gap = 2
        for lvl in LEVELS:
            n = counts[lvl]
            if not n:
                continue
            seg = w * n / total
            c.create_rectangle(x, 0, max(x + seg - gap, x + 1), h,
                               fill=LEVEL_COLORS[lvl], outline="")
            x += seg

    def _set_level(self, key):
        self.filter_level = key
        self._refresh_chips()
        self._render_table()

    
    def load_file(self):
        path = filedialog.askopenfilename(filetypes=[("EVTX", "*.evtx")])
        if path:
            self.path_label.configure(text=path, text_color=TEXT)
            self.evtx_path = path
            self.batch_dir = None
            self._status(f"● Datei geladen: {Path(path).name}", ACCENT_HOVER)

    def load_batch_dir(self):
        path = filedialog.askdirectory(title="Ordner mit EVTX-Dateien auswählen")
        if path:
            self.path_label.configure(text=f"Ordner: {path}", text_color=TEXT)
            self.batch_dir = path
            self.evtx_path = None
            self._status(f"● Ordner ausgewählt: {path}", ACCENT_HOVER)

    
    def scan(self):
        if self._scanning:
            return
        if not self.evtx_path and not self.batch_dir:
            messagebox.showwarning("Warnung", "Bitte zuerst eine EVTX-Datei oder einen Ordner auswählen")
            return

        self._set_busy(True, determinate=bool(self.batch_dir))
        self._status("● Scannen…", ACCENT_HOVER)
        threading.Thread(target=self._scan_worker,
                         args=(self.evtx_path, self.batch_dir), daemon=True).start()

    def _set_busy(self, busy, determinate=False):
        self._scanning = busy
        if busy:
            self.scan_btn.configure(state="disabled", text="⏳   Scanne…")
            self.progress.pack(side="right", padx=(0, 12))
            if determinate:
                self.progress.configure(mode="determinate")
                self.progress.set(0)
            else:
                self.progress.configure(mode="indeterminate")
                self.progress.start()
        else:
            self.progress.stop()
            self.progress.pack_forget()
            self.scan_btn.configure(state="normal", text="⚡   Scannen")

    def _scan_worker(self, evtx_path, batch_dir):
        try:
            rules = load_rules(get_base_path() / "rules")
            if batch_dir:
                report, text = self._scan_batch(rules, batch_dir)
            else:
                report, text = self._scan_single(rules, evtx_path)
            self._q.put(("scan_done", report, text))
        except Exception as e:
            self._q.put(("scan_error", str(e)))

    def _scan_single(self, rules, evtx_path):
        events = read_events(Path(evtx_path))
        report = scan_events(events, rules, file_path=evtx_path)
        text = (f"● {report['total_events']:,} Ereignisse — "
                f"{report['total_matches']} Treffer")
        return report, text

    def _scan_batch(self, rules, batch_dir):
        evtx_files = sorted(Path(batch_dir).rglob("*.evtx"))
        n = len(evtx_files)
        all_matches = []
        total_events = 0
        files_with_matches = 0

        for i, evtx in enumerate(evtx_files, 1):
            try:
                events = read_events(evtx)
            except Exception:
                events = None
            if events:
                total_events += len(events)
                report = scan_events(events, rules, file_path=str(evtx))
                if report["total_matches"] > 0:
                    files_with_matches += 1
                    for m in report["matches"]:
                        m["file"] = str(evtx)
                        all_matches.append(m)
            self._q.put(("progress", i, n))

        report = {
            "total_events": total_events,
            "total_matches": len(all_matches),
            "rules_with_matches": sorted({m["rule_title"] for m in all_matches}),
            "matches": all_matches,
            "file": batch_dir,
        }
        text = (f"● {n} Dateien — {files_with_matches} mit Treffern — "
                f"{len(all_matches)} Treffer")
        return report, text

    
    def _poll_queue(self):
        try:
            while True:
                item = self._q.get_nowait()
                try:
                    self._handle_item(item)
                except Exception:
                    import traceback
                    traceback.print_exc()
        except queue.Empty:
            pass
        self.after(80, self._poll_queue)

    def _handle_item(self, item):
        kind = item[0]
        if kind == "progress":
            _, i, n = item
            if n:
                self.progress.set(i / n)
            self._status(f"● Scannen… ({i}/{n})", ACCENT_HOVER)
        elif kind == "scan_done":
            _, report, text = item
            self._set_busy(False)
            self.report = report
            self.all_matches = report["matches"]
            self.live_matches = []
            self._update_stats()
            self._render_table()
            ok = report.get("total_matches", 0) == 0
            self._status(text, GREEN if ok else AMBER)
        elif kind == "scan_error":
            _, msg = item
            self._set_busy(False)
            messagebox.showerror("Fehler", f"Scan fehlgeschlagen:\n{msg}")
            self._status("● Fehler beim Scannen", CRITICAL)
        elif kind == "live":
            _, event_type, data = item
            if event_type == "match":
                self._add_live_match(data)
            elif event_type in ("started", "error"):
                self._status(f"● {data}", CRITICAL if event_type == "error" else GREEN)

    
    def _update_stats(self):
        matches = self._combined()
        events = self.report.get("total_events", 0) if self.report else 0
        self._set_stat(self.stat_events, events)
        self._set_stat(self.stat_matches, len(matches))
        self._set_stat(self.stat_rules, len({m.get("rule_title") for m in matches}))
        self._set_stat(self.stat_crit,
                       sum(1 for m in matches if m.get("level") in ("critical", "high")))
        self._refresh_chips()
        self._draw_bar()

    
    def _passes(self, m):
        level = m.get("level", "informational")
        if self.filter_level != "all" and level != self.filter_level:
            return False
        if self.search_text:
            haystack = f"{m.get('rule_title', '')} {m.get('event', {})}".lower()
            if self.search_text not in haystack:
                return False
        return True

    def _insert_row(self, m, index="end"):
        level = m.get("level", "informational")
        ev = m.get("event", {}) or {}
        ts = (ev.get("TimeCreated", "") if isinstance(ev, dict) else "") or ""
        self._row_counter += 1
        iid = f"r{self._row_counter}"
        zebra = "odd" if self._row_counter % 2 else "even"
        self.tree.insert("", index, iid=iid, values=(
            LEVEL_ICONS.get(level, "⚪"), m.get("rule_title", ""), level.upper(),
            m.get("event_index", "-"), ts, _summarize(ev),
        ), tags=(level, zebra))
        self._rows[iid] = m

    def _render_table(self):
        for row in self.tree.get_children():
            self.tree.delete(row)
        self._rows.clear()
        self._row_counter = 0

        scanned = sorted(
            self.all_matches,
            key=lambda m: (
                SEVERITY_ORDER.get(m.get("level", "informational"), 5),
                str((m.get("event", {}) or {}).get("TimeCreated", "") or "")
            )
        )

        shown = 0
        for m in self.live_matches + scanned:
            if self._passes(m):
                self._insert_row(m)
                shown += 1

        total = len(self._combined())
        self.count_label.configure(text=f"{shown:,} von {total:,} angezeigt" if total else "")
        self._update_empty_state(shown, total)

    def _update_empty_state(self, shown, total):
        if shown > 0:
            self.empty.place_forget()
            return
        if total > 0:
            text = "🔍\nKeine Treffer für diesen Filter"
        elif self.report is not None:
            text = "✅\nKeine Treffer — alles sauber!"
        else:
            text = ("🐾\nNoch nichts gefunden\n"
                    "Wähle eine EVTX-Datei oder einen Ordner und starte den Scan (F5)")
        self.empty.configure(text=text)
        self.empty.place(relx=0.5, rely=0.5, anchor="center")
        self.empty.lift()

    def _apply_filter(self):
        self.search_text = self.search_var.get().strip().lower()
        self._render_table()

    
    def _set_detail_placeholder(self):
        self.detail.configure(state="normal")
        self.detail.delete("1.0", "end")
        self.detail.insert("end", "Wähle einen Treffer in der Tabelle, um alle Details zu sehen.", "meta")
        self.detail.configure(state="disabled")

    def _on_select(self, _event=None):
        sel = self.tree.selection()
        if not sel:
            return
        m = self._rows.get(sel[0])
        if m:
            self._show_detail(m)

    def _show_detail(self, m):
        level = m.get("level", "informational")
        ev = m.get("event", {})
        try:
            body = json.dumps(ev, ensure_ascii=False, indent=2, default=str)
        except Exception:
            body = str(ev)

        d = self.detail
        d.configure(state="normal")
        d.delete("1.0", "end")
        d.insert("end", f"{m.get('rule_title', '')}", "title")
        d.insert("end", f"   [{level.upper()}]", f"lvl_{level if level in LEVEL_COLORS else 'informational'}")
        meta = f"   Ereignis #{m.get('event_index', '-')}"
        if m.get("file"):
            meta += f"   ·   {m['file']}"
        d.insert("end", meta + "\n\n", "meta")
        d.insert("end", body)
        d.configure(state="disabled")

    def _copy_to_clipboard(self, text):
        self.clipboard_clear()
        self.clipboard_append(text)
        self._status("● In die Zwischenablage kopiert", GREEN)

    def _copy_detail(self):
        text = self.detail.get("1.0", "end").strip()
        if text:
            self._copy_to_clipboard(text)

    def _popup_menu(self, event):
        iid = self.tree.identify_row(event.y)
        if not iid:
            return
        self.tree.selection_set(iid)
        try:
            self.menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.menu.grab_release()

    def _selected_match(self):
        sel = self.tree.selection()
        return self._rows.get(sel[0]) if sel else None

    def _copy_rule(self):
        m = self._selected_match()
        if m:
            self._copy_to_clipboard(str(m.get("rule_title", "")))

    def _copy_event_json(self):
        m = self._selected_match()
        if m:
            self._copy_to_clipboard(json.dumps(m.get("event", {}), ensure_ascii=False,
                                               indent=2, default=str))

    def _filter_by_rule(self):
        m = self._selected_match()
        if m:
            self.search_var.set(str(m.get("rule_title", "")))

    
    def save_json(self):
        if not self.report:
            messagebox.showinfo("Info", "Bitte zuerst scannen")
            return
        path = filedialog.asksaveasfilename(defaultextension=".json",
                                            filetypes=[("JSON", "*.json")])
        if path:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(self.report, f, ensure_ascii=False, indent=2, default=str)
            messagebox.showinfo("Erfolg", "Gespeichert")
            self._status(f"● JSON gespeichert: {Path(path).name}", GREEN)

    def save_html(self):
        if not self.report:
            messagebox.showinfo("Info", "Bitte zuerst scannen")
            return
        path = filedialog.asksaveasfilename(defaultextension=".html",
                                            filetypes=[("HTML", "*.html")])
        if path:
            try:
                from zen.html_report import generate_html_report
                generate_html_report(self.report, Path(path))
                messagebox.showinfo("Erfolg", "HTML-Bericht gespeichert")
                self._status(f"● HTML gespeichert: {Path(path).name}", GREEN)
            except Exception as e:
                messagebox.showerror("Fehler", f"HTML-Bericht fehlgeschlagen:\n{e}")

    
    def toggle_live_monitor(self):
        if self.live_active:
            if self.live_monitor:
                self.live_monitor.stop()
            self.live_active = False
            self.live_btn.configure(text="📡   Live Monitor", fg_color="transparent",
                                    hover_color=ELEV, border_color=BORDER)
            self.live_badge.configure(text="")
            self._status("● Live-Überwachung gestoppt", MUTED)
            return

        channel = self.live_channel.get()
        try:
            self.live_monitor = LiveMonitor(channel, get_base_path() / "rules", self.on_live_event)
            self.live_monitor.start()
            self.live_active = True
            self.live_btn.configure(text="■   Live stoppen", fg_color=DANGER,
                                    hover_color="#f85149", border_color=DANGER)
            self.live_badge.configure(text=f"●  LIVE  ·  {channel}")
            self._status(f"● Live-Überwachung aktiv: {channel}", GREEN)
            self._start_pulse()
        except Exception as e:
            messagebox.showerror("Fehler", f"Live-Monitor konnte nicht starten:\n{e}")

    def _start_pulse(self):
        if self._pulse_running:
            return
        self._pulse_running = True
        self._pulse()

    def _pulse(self):
        if not self.live_active:
            self._pulse_running = False
            return
        self._pulse_state = not self._pulse_state
        self.live_badge.configure(
            text_color=CRITICAL if self._pulse_state else _mix(CRITICAL, SIDEBAR, 0.6))
        self.after(650, self._pulse)

    def on_live_event(self, event_type, data):
        self._q.put(("live", event_type, data))

    def _add_live_match(self, data):
        level = data.get("level", "informational")
        data.setdefault("event_index", "-")
        self.live_matches.insert(0, data)

        if self._passes(data):
            self._insert_row(data, index=0)
            self.empty.place_forget()

        self._update_stats()
        shown = len(self.tree.get_children())
        total = len(self._combined())
        self.count_label.configure(text=f"{shown:,} von {total:,} angezeigt")
        self._status(f"● 🚨 Live-Treffer: {data.get('rule_title', '')} ({level})",
                     LEVEL_COLORS.get(level, MUTED))

    
    def _on_close(self):
        try:
            if self.live_monitor and self.live_active:
                self.live_monitor.stop()
        except Exception:
            pass
        self.destroy()


def main():
    set_taskbar_icon()
    app = ZenApp()
    app.mainloop()


if __name__ == "__main__":
    main()