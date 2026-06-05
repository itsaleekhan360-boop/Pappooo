import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import re
import math

# ── Analysis engine ───────────────────────────────────────────────────────────
SPAM_KEYWORDS = {
    "Financial Scam": [
        "free money", "you won", "prize", "lottery", "claim now",
        "bank account", "wire transfer", "cash prize", "million dollars",
        "inheritance", "winner", "jackpot", "earn money fast",
    ],
    "Phishing": [
        "verify your account", "click here", "update your password",
        "confirm your email", "login now", "suspended account",
        "unusual activity", "unauthorized access", "reset your password",
        "your account has been", "verify immediately",
    ],
    "Malware": [
        "download now", "free software", "crack version", "keygen",
        "activate now", "serial key", "patch download",
    ],
    "Urgency": [
        "act now", "limited time", "expires soon", "urgent",
        "last chance", "do not ignore", "immediate action",
        "respond immediately", "deadline today",
    ],
    "Adult Content": [
        "adult content", "18+", "hot singles", "meet girls",
        "dating site", "explicit content",
    ],
    "Fake Health": [
        "lose weight fast", "miracle cure", "diet pill",
        "guaranteed results", "risk free trial", "100% safe",
        "doctors hate", "slim fast",
    ],
}

REGEX_PATTERNS = [
    (r"\b[A-Z]{4,}\b",                     "ALL-CAPS words"),
    (r"!{2,}",                              "Multiple exclamation marks"),
    (r"\$\d+",                              "Dollar amount"),
    (r"https?://\S+",                       "URL detected"),
    (r"\b\d{10,}\b",                        "Long numeric string"),
    (r"(?i)\bfree\b",                       "Keyword: FREE"),
    (r"(?i)\bgift\b",                       "Keyword: GIFT"),
    (r"(?i)\boffer\b",                      "Keyword: OFFER"),
    (r"(?i)dear\s+(sir|madam|friend|user)", "Generic salutation"),
    (r"(?i)\bunsubscribe\b",                "Unsubscribe link"),
]


class SpamDFA:
    TRANSITIONS = {
        ("q0", 0): "q0", ("q0", 1): "q1",
        ("q1", 1): "q1", ("q1", 2): "q2",
        ("q2", 1): "q2", ("q2", 2): "q3",
        ("q3", 1): "q3", ("q3", 2): "q3",
    }

    def run(self, hits: int) -> str:
        state, rem = "q0", hits
        while rem > 0:
            step = min(rem, 2)
            state = self.TRANSITIONS.get((state, step), state)
            rem -= step
        return state


def analyze_email(text: str) -> dict:
    tl = text.lower()
    dfa = SpamDFA()
    kw_hits, total_kw = {}, 0
    for cat, kws in SPAM_KEYWORDS.items():
        found = [k for k in kws if k in tl]
        if found:
            kw_hits[cat] = found
            total_kw += len(found)
    re_hits = [(lbl, len(re.findall(pat, text)))
               for pat, lbl in REGEX_PATTERNS if re.search(pat, text)]
    state    = dfa.run(total_kw)
    accepted = (state == "q3")
    score    = min(int(((total_kw + len(re_hits) * 0.5) / 20) * 100), 100)
    if accepted and score < 70:
        score = 70
    verdict = "SPAM" if (score >= 60 or accepted) else "SUSPICIOUS" if score >= 30 else "SAFE"
    return {"verdict": verdict, "score": score, "state": state,
            "accepted": accepted, "kw_hits": kw_hits,
            "total_kw": total_kw, "re_hits": re_hits}


# ── Design tokens ─────────────────────────────────────────────────────────────
BG       = "#070B14"   # deep space background
PANEL    = "#0C1220"   # panel bg
CARD     = "#0F1729"   # card bg
BORDER   = "#1A2D4A"   # card border
LINE     = "#162338"   # divider
BLUE     = "#3B82F6"   # primary blue
BLUE_DIM = "#1D4ED8"   # darker blue
CYAN     = "#22D3EE"   # cyan accent
TEXT     = "#E2E8F0"   # primary text
SUB      = "#94A3B8"   # secondary text
MUTED    = "#3E5070"   # muted elements
GREEN    = "#10B981"   # safe
AMBER    = "#F59E0B"   # suspicious
RED      = "#EF4444"   # spam

# Verdict config: (fg, track_color, glow)
VERDICT_CFG = {
    "SPAM":       (RED,   "#2D0A0A", "#7F1D1D"),
    "SUSPICIOUS": (AMBER, "#2D1F0A", "#78350F"),
    "SAFE":       (GREEN, "#052512", "#064E3B"),
}

# DFA node colors: (ring_idle, ring_active, fill_active)
DFA_NODE = {
    "q0": ("#334155", "#818CF8"),
    "q1": ("#334155", "#84CC16"),
    "q2": ("#334155", "#F97316"),
    "q3": ("#334155", "#EF4444"),
}

F_TITLE = ("Segoe UI", 12, "bold")
F_HEAD  = ("Segoe UI", 10, "bold")
F_BODY  = ("Segoe UI",  9)
F_SMALL = ("Segoe UI",  8)
F_MONO  = ("Consolas",  9)
F_HUGE  = ("Segoe UI", 38, "bold")
F_BADGE = ("Segoe UI", 11, "bold")


# ── Arc gauge (replaces progress bar) ────────────────────────────────────────
class ArcGauge(tk.Canvas):
    """Animated donut gauge showing spam score 0–100 %."""

    RING_W = 18
    RADIUS = 58

    def __init__(self, parent, **kw):
        size = (self.RADIUS + 4) * 2 + self.RING_W
        super().__init__(parent, width=size, height=size,
                         bg=CARD, highlightthickness=0, **kw)
        self.cx = self.cy = size // 2
        self._score = 0
        self._color = MUTED
        self._label = ""
        self._draw(0)

    def _draw(self, score):
        self.delete("all")
        cx, cy = self.cx, self.cy
        r = self.RADIUS
        rw = self.RING_W

        # Track ring (full circle)
        self.create_arc(cx-r, cy-r, cx+r, cy+r,
                        start=0, extent=359.9,
                        style="arc", outline=LINE, width=rw)

        # Score arc (clockwise from top = 90°)
        if score > 0:
            extent = -(score / 100) * 359.9
            self.create_arc(cx-r, cy-r, cx+r, cy+r,
                            start=90, extent=extent,
                            style="arc", outline=self._color, width=rw)

        # Center: percentage
        disp = f"{score}%" if score > 0 else "—"
        self.create_text(cx, cy - 8,
                         text=disp,
                         font=("Segoe UI", 20, "bold"),
                         fill=self._color if score > 0 else MUTED)

        # Center: verdict label
        if self._label:
            self.create_text(cx, cy + 14,
                             text=self._label,
                             font=("Segoe UI", 8, "bold"),
                             fill=self._color)

    def animate_to(self, target, color, label, _step=0, _frames=40):
        self._color = color
        self._label = label
        t = _step / _frames
        eased = 1 - (1 - t) ** 3         # ease-out cubic
        current = int(target * eased)
        self._draw(current)
        if _step < _frames:
            self.after(16, lambda: self.animate_to(
                target, color, label, _step + 1, _frames))

    def reset(self):
        self._color = MUTED
        self._label = ""
        self._draw(0)


# ── Animated globe ────────────────────────────────────────────────────────────
class Globe(tk.Canvas):
    def __init__(self, parent, size=154, **kw):
        super().__init__(parent, width=size, height=size,
                         bg=CARD, highlightthickness=0, **kw)
        self.size = size
        self.cx = self.cy = size // 2
        self.r  = size // 2 - 12
        self.angle = 0
        self._draw()

    def _proj(self, lat, lon):
        la = math.radians(lat)
        lo = math.radians(lon + self.angle)
        x  = math.cos(la) * math.sin(lo)
        y  = math.sin(la)
        z  = math.cos(la) * math.cos(lo)
        if z < 0:
            return None
        return self.cx + x * self.r, self.cy - y * self.r

    def _draw(self):
        self.delete("all")
        r = self.r
        # Ambient glow ring
        self.create_oval(self.cx-r-6, self.cy-r-6, self.cx+r+6, self.cy+r+6,
                         outline="#0B2040", width=1)
        # Sphere base
        self.create_oval(self.cx-r, self.cy-r, self.cx+r, self.cy+r,
                         fill="#050D1C", outline=BLUE_DIM, width=1)
        # Grid lines
        for lat in range(-75, 90, 20):
            pts = [p for p in (self._proj(lat, lo) for lo in range(0, 366, 5)) if p]
            for i in range(len(pts)-1):
                self.create_line(*pts[i], *pts[i+1], fill=BORDER, width=1)
        for lon in range(0, 360, 20):
            pts = [p for p in (self._proj(la, lon) for la in range(-90, 91, 5)) if p]
            for i in range(len(pts)-1):
                self.create_line(*pts[i], *pts[i+1], fill=BORDER, width=1)
        # Land dots
        for lat, lon in (
            [(la, lo) for la in range(30, 70, 7) for lo in range(-130, -60, 9)] +
            [(la, lo) for la in range(-55, 15, 7) for lo in range(-80, -35, 9)] +
            [(la, lo) for la in range(36, 70, 6)  for lo in range(-10, 40, 7)]  +
            [(la, lo) for la in range(-35, 37, 6) for lo in range(-18, 52, 7)]  +
            [(la, lo) for la in range(10, 75, 6)  for lo in range(40, 145, 7)] +
            [(la, lo) for la in range(-44, -10, 6) for lo in range(114, 154, 7)]
        ):
            p = self._proj(lat, lon)
            if p:
                self.create_oval(p[0]-2, p[1]-2, p[0]+2, p[1]+2,
                                 fill=CYAN, outline="")
        # Equator
        eq = [p for p in (self._proj(0, lo) for lo in range(0, 366, 4)) if p]
        for i in range(len(eq)-1):
            self.create_line(*eq[i], *eq[i+1], fill=CYAN, width=1)

    def animate(self):
        self.angle = (self.angle + 1) % 360
        self._draw()
        self.after(30, self.animate)


# ── DFA diagram with animated node traversal ─────────────────────────────────
class DFACanvas(tk.Canvas):
    NODES = [("q0", 20, 70), ("q1", 68, 24), ("q2", 128, 24), ("q3", 162, 80)]

    def __init__(self, parent, **kw):
        super().__init__(parent, width=186, height=148,
                         bg=CARD, highlightthickness=0, **kw)
        self._active = set()
        self._draw()

    def _draw(self):
        self.delete("all")
        pos = {}
        for sid, x, y in self.NODES:
            idle, active = DFA_NODE[sid]
            lit = sid in self._active
            r = 17
            # Double ring for accepting state
            if sid == "q3":
                self.create_oval(x-r-5, y-r-5, x+r+5, y+r+5,
                                 outline=active if lit else idle,
                                 width=1, dash=(4, 3))
            # Node fill
            fill = CARD if lit else PANEL
            self.create_oval(x-r, y-r, x+r, y+r,
                             fill=fill, outline=active if lit else idle,
                             width=2 if lit else 1)
            self.create_text(x, y, text=sid,
                             font=("Consolas", 8, "bold"),
                             fill=active if lit else idle)
            pos[sid] = (x, y, r)

        # Arrows q0→q1→q2→q3
        for a, b in [("q0","q1"), ("q1","q2"), ("q2","q3")]:
            x1,y1,r1 = pos[a]; x2,y2,r2 = pos[b]
            dx, dy = x2-x1, y2-y1
            d  = math.hypot(dx, dy) or 1
            sx, sy = x1 + dx/d*r1, y1 + dy/d*r1
            ex, ey = x2 - dx/d*r2, y2 - dy/d*r2
            both_lit = a in self._active and b in self._active
            col = CYAN if both_lit else MUTED
            self.create_line(sx, sy, ex, ey, arrow=tk.LAST,
                             fill=col, width=1, arrowshape=(6,8,3))

        # Self-loop on q3
        x, y, _ = pos["q3"]
        lit = "q3" in self._active
        self.create_arc(x-18, y-34, x+18, y-2,
                        start=0, extent=260, style="arc",
                        outline=RED if lit else MUTED, width=1)

        self.create_text(93, 136, text="q0  →  q1  →  q2  →  q3",
                         font=("Segoe UI", 7), fill=MUTED)

    def traverse_to(self, final_state, _idx=0):
        """Animate DFA by lighting up nodes one by one up to final_state."""
        order = ["q0", "q1", "q2", "q3"]
        target_i = order.index(final_state)
        if _idx <= target_i:
            self._active = set(order[:_idx+1])
            self._draw()
            self.after(220, lambda: self.traverse_to(final_state, _idx+1))

    def reset(self):
        self._active = set()
        self._draw()


# ── Scan pulse (shown while "analyzing") ─────────────────────────────────────
class ScanPulse(tk.Canvas):
    """Animated horizontal scan line — purely decorative feedback."""

    def __init__(self, parent, w, h=3, **kw):
        super().__init__(parent, width=w, height=h,
                         bg=CARD, highlightthickness=0, **kw)
        self._w = w
        self._h = h
        self._pos  = 0
        self._going = False

    def start(self, text_widget_height):
        self._total_h = text_widget_height
        self._going   = True
        self._pos     = 0
        self._step()

    def _step(self):
        if not self._going:
            return
        self.delete("all")
        self.create_rectangle(0, 0, self._w, self._h, fill=CYAN, outline="")
        # We just pulse the bar color
        self.after(40, self._step)

    def stop(self):
        self._going = False
        self.delete("all")


# ── Main application ──────────────────────────────────────────────────────────
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("SpamGuard — Theory of Automata | IQRA University")
        self.configure(bg=BG)
        self.geometry("1120x720")
        self.minsize(920, 620)
        self._build()
        self.globe.animate()

    # ── Layout ────────────────────────────────────────────────────────────────

    def _build(self):
        self._nav()
        body = tk.Frame(self, bg=BG)
        body.pack(fill="both", expand=True, padx=16, pady=12)

        left = tk.Frame(body, bg=BG)
        left.pack(side="left", fill="both", expand=True)

        right = tk.Frame(body, bg=BG, width=210)
        right.pack(side="right", fill="y", padx=(12, 0))
        right.pack_propagate(False)

        self._left_panel(left)
        self._right_panel(right)

    def _nav(self):
        nav = tk.Frame(self, bg=PANEL, height=50)
        nav.pack(fill="x")
        nav.pack_propagate(False)
        tk.Frame(self, bg=BORDER, height=1).pack(fill="x")

        inner = tk.Frame(nav, bg=PANEL)
        inner.pack(fill="both", padx=20)

        # Logo area
        logo_f = tk.Frame(inner, bg=PANEL)
        logo_f.pack(side="left", pady=12)

        dot = tk.Canvas(logo_f, width=8, height=8, bg=PANEL,
                        highlightthickness=0)
        dot.pack(side="left", padx=(0, 8))
        dot.create_oval(0, 0, 8, 8, fill=CYAN, outline="")
        self._pulse_dot(dot)

        tk.Label(logo_f, text="SPAMGUARD", font=("Segoe UI", 12, "bold"),
                 bg=PANEL, fg=TEXT).pack(side="left")
        tk.Label(logo_f, text="  /  AUTOMATA ENGINE",
                 font=("Segoe UI", 9), bg=PANEL, fg=MUTED).pack(side="left")

        # Right meta
        meta = tk.Frame(inner, bg=PANEL)
        meta.pack(side="right", pady=12)
        tk.Label(meta, text="IQRA University  ·  Theory of Automata  ·  DFA / Regex",
                 font=("Segoe UI", 8), bg=PANEL, fg=MUTED).pack()

    def _pulse_dot(self, canvas, toggle=True):
        canvas.delete("all")
        color = CYAN if toggle else BLUE_DIM
        canvas.create_oval(0, 0, 8, 8, fill=color, outline="")
        canvas.after(800, lambda: self._pulse_dot(canvas, not toggle))

    # ── Left panel ────────────────────────────────────────────────────────────

    def _left_panel(self, p):
        # ── Input card ────────────────────────────────────────
        ic = self._card(p)
        ic.pack(fill="both", expand=True, pady=(0, 10))

        hdr = tk.Frame(ic, bg=CARD)
        hdr.pack(fill="x", pady=(0, 10))
        tk.Label(hdr, text="EMAIL ANALYSIS", font=F_HEAD,
                 bg=CARD, fg=TEXT).pack(side="left")
        self._tag(hdr, "DFA POWERED", CYAN).pack(side="right")

        self.txt = scrolledtext.ScrolledText(
            ic, height=9, wrap="word", font=F_MONO,
            bg=PANEL, fg=TEXT, insertbackground=CYAN,
            selectbackground=BORDER,
            relief="flat", borderwidth=0, padx=14, pady=12)
        self.txt.pack(fill="both", expand=True)

        self._ph = "Paste the full email body here to begin analysis..."
        self.txt.insert("1.0", self._ph)
        self.txt.configure(fg=MUTED)
        self.txt.bind("<FocusIn>",  self._ph_clear)
        self.txt.bind("<FocusOut>", self._ph_restore)

        # Scan pulse bar (sits between textarea and buttons)
        self.scan_bar = tk.Frame(ic, bg=BORDER, height=1)
        self.scan_bar.pack(fill="x", pady=(8, 0))
        self._scan_anim_id = None

        br = tk.Frame(ic, bg=CARD)
        br.pack(fill="x", pady=(10, 0))

        self.analyze_btn = self._btn_primary(br, "▶  ANALYZE", self._analyze)
        self.analyze_btn.pack(side="left")
        self._btn_ghost(br, "Spam Sample", self._load_spam).pack(side="left", padx=(10, 0))
        self._btn_ghost(br, "Safe Sample", self._load_safe).pack(side="left", padx=(6, 0))
        self._btn_ghost(br, "Clear", self._clear, danger=True).pack(side="right")

        # ── Results card ──────────────────────────────────────
        rc = self._card(p)
        rc.pack(fill="both", expand=True)

        hdr2 = tk.Frame(rc, bg=CARD)
        hdr2.pack(fill="x", pady=(0, 10))
        tk.Label(hdr2, text="ANALYSIS REPORT", font=F_HEAD,
                 bg=CARD, fg=TEXT).pack(side="left")
        self.status_tag = self._tag(hdr2, "READY", MUTED)
        self.status_tag.pack(side="right")

        row = tk.Frame(rc, bg=CARD)
        row.pack(fill="both", expand=True)

        # Gauge + verdict column
        gv = tk.Frame(row, bg=CARD, width=162)
        gv.pack(side="left", fill="y")
        gv.pack_propagate(False)

        self.gauge = ArcGauge(gv)
        self.gauge.pack(pady=(4, 12))

        tk.Frame(gv, bg=LINE, height=1).pack(fill="x")

        vf = tk.Frame(gv, bg=CARD, pady=12, padx=8)
        vf.pack(fill="x")
        tk.Label(vf, text="VERDICT", font=F_SMALL, bg=CARD, fg=MUTED).pack(anchor="w")
        self.v_lbl = tk.Label(vf, text="—", font=F_BADGE, bg=CARD, fg=MUTED)
        self.v_lbl.pack(anchor="w", pady=(3, 0))

        tk.Frame(gv, bg=LINE, height=1).pack(fill="x")

        sf = tk.Frame(gv, bg=CARD, pady=10, padx=8)
        sf.pack(fill="x")
        tk.Label(sf, text="DFA STATE", font=F_SMALL, bg=CARD, fg=MUTED).pack(anchor="w")
        self.st_lbl = tk.Label(sf, text="—",
                               font=("Consolas", 13, "bold"), bg=CARD, fg=CYAN)
        self.st_lbl.pack(anchor="w", pady=(3, 0))

        # Vertical divider
        tk.Frame(row, bg=LINE, width=1).pack(side="left", fill="y", padx=(12, 0))

        # Detail log
        self.detail = scrolledtext.ScrolledText(
            row, font=F_MONO, bg=PANEL, fg=SUB,
            state="disabled", relief="flat", borderwidth=0,
            padx=14, pady=12, selectbackground=BORDER)
        self.detail.pack(side="left", fill="both", expand=True)

    # ── Right panel ───────────────────────────────────────────────────────────

    def _right_panel(self, p):
        # Globe card
        gc = self._card(p)
        gc.pack(fill="x")
        hdr = tk.Frame(gc, bg=CARD)
        hdr.pack(fill="x", pady=(0, 8))
        tk.Label(hdr, text="LIVE GLOBE", font=F_HEAD, bg=CARD, fg=TEXT).pack(side="left")
        self._tag(hdr, "ROTATING", CYAN).pack(side="right")
        self.globe = Globe(gc, size=154)
        self.globe.pack()

        # DFA diagram card
        dc = self._card(p)
        dc.pack(fill="x", pady=(10, 0))
        hdr2 = tk.Frame(dc, bg=CARD)
        hdr2.pack(fill="x", pady=(0, 8))
        tk.Label(hdr2, text="DFA MACHINE", font=F_HEAD, bg=CARD, fg=TEXT).pack(side="left")
        self._tag(hdr2, "ANIMATED", BLUE).pack(side="right")
        self.dfa = DFACanvas(dc)
        self.dfa.pack()

        # Stats card
        sc = self._card(p)
        sc.pack(fill="x", pady=(10, 0))
        tk.Label(sc, text="STATS", font=F_HEAD, bg=CARD, fg=TEXT).pack(anchor="w", pady=(0, 8))

        self.stat_kw  = self._stat_row(sc, "Keyword hits", "—")
        self.stat_re  = self._stat_row(sc, "Regex matches", "—")
        self.stat_acc = self._stat_row(sc, "DFA accepted", "—")

        tk.Frame(sc, bg=LINE, height=1).pack(fill="x", pady=(10, 8))

        for name in ("Moniza Fatima", "Laraib Suikarno"):
            tk.Label(sc, text=name, font=F_SMALL, bg=CARD, fg=MUTED).pack(anchor="w")
        tk.Label(sc, text="Miss Alisha Farmaan", font=F_SMALL,
                 bg=CARD, fg=MUTED).pack(anchor="w")

    def _stat_row(self, parent, label, value):
        f = tk.Frame(parent, bg=CARD)
        f.pack(fill="x", pady=2)
        tk.Label(f, text=label, font=F_SMALL, bg=CARD, fg=MUTED).pack(side="left")
        lbl = tk.Label(f, text=value, font=("Consolas", 9, "bold"), bg=CARD, fg=SUB)
        lbl.pack(side="right")
        return lbl

    # ── Widget helpers ────────────────────────────────────────────────────────

    def _card(self, parent):
        outer = tk.Frame(parent, bg=BORDER, padx=1, pady=1)
        inner = tk.Frame(outer, bg=CARD, padx=14, pady=12)
        inner.pack(fill="both", expand=True)
        # Wrap pack so calling code packs outer automatically
        _orig_pack = inner.pack

        def _smart_pack(**kw):
            outer.pack(**kw)
        inner.pack = _smart_pack    # redirect inner.pack → outer.pack
        return inner

    # Map accent colors to muted bg equivalents for tag backgrounds
    _TAG_BG = {
        "#22D3EE": "#0C2A30",  # CYAN
        "#3B82F6": "#0C1A30",  # BLUE
        "#EF4444": "#2D0A0A",  # RED
        "#F59E0B": "#2D1F0A",  # AMBER
        "#10B981": "#052512",  # GREEN
        "#3E5070": "#131C28",  # MUTED
    }

    def _tag(self, parent, text, color):
        bg = self._TAG_BG.get(color, PANEL)
        f = tk.Frame(parent, bg=bg, padx=6, pady=2)
        tk.Label(f, text=text, font=("Segoe UI", 7, "bold"),
                 bg=bg, fg=color).pack()
        return f

    def _btn_primary(self, parent, text, cmd):
        return tk.Button(parent, text=text, command=cmd,
                         font=("Segoe UI", 9, "bold"),
                         bg=BLUE, fg="white", activebackground=BLUE_DIM,
                         activeforeground="white", relief="flat",
                         cursor="hand2", padx=16, pady=7, bd=0)

    def _btn_ghost(self, parent, text, cmd, danger=False):
        fg = RED if danger else SUB
        return tk.Button(parent, text=text, command=cmd, font=F_BODY,
                         bg=PANEL, fg=fg, activebackground=CARD,
                         activeforeground=fg, relief="flat",
                         cursor="hand2", padx=12, pady=7, bd=0)

    # ── Placeholder ───────────────────────────────────────────────────────────

    def _ph_clear(self, _=None):
        if self.txt.get("1.0", "end-1c") == self._ph:
            self.txt.delete("1.0", "end")
            self.txt.configure(fg=TEXT)

    def _ph_restore(self, _=None):
        if not self.txt.get("1.0", "end-1c").strip():
            self.txt.insert("1.0", self._ph)
            self.txt.configure(fg=MUTED)

    # ── Samples ───────────────────────────────────────────────────────────────

    def _load_spam(self):
        self._set("DEAR USER!! You have WON a $1,000,000 LOTTERY PRIZE!\n"
                  "Click here to CLAIM NOW and verify your account immediately.\n"
                  "LIMITED TIME offer – ACT NOW before it expires!\n"
                  "Download now FREE software to activate your reward.\n"
                  "Wire transfer details required. Respond immediately.\n"
                  "Visit: https://claim-prize.free.net/verify?id=12345678901234\n"
                  "Unsubscribe | Risk free trial | 100% Safe Guaranteed!!")

    def _load_safe(self):
        self._set("Hi Alex,\n\nI hope you are doing well. Please find attached "
                  "the meeting notes from yesterday's discussion.\n\n"
                  "The team meeting is Thursday at 3 PM in conference room B. "
                  "Please bring your laptop and the quarterly report.\n\n"
                  "Best regards,\nSarah\nProject Manager")

    def _set(self, txt):
        self.txt.configure(fg=TEXT)
        self.txt.delete("1.0", "end")
        self.txt.insert("1.0", txt)

    # ── Clear ─────────────────────────────────────────────────────────────────

    def _clear(self):
        self.txt.delete("1.0", "end")
        self._ph_restore()
        self.gauge.reset()
        self.v_lbl.configure(text="—", fg=MUTED)
        self.st_lbl.configure(text="—", fg=CYAN)
        self._update_status_tag("READY", MUTED)
        self.stat_kw.configure(text="—")
        self.stat_re.configure(text="—")
        self.stat_acc.configure(text="—")
        self.dfa.reset()
        self._set_detail("")

    # ── Scan bar animation ────────────────────────────────────────────────────

    def _scan_start(self):
        self._scan_colors = [CYAN, BLUE, CYAN, BLUE_DIM, BORDER]
        self._scan_idx = 0
        self._scan_tick()

    def _scan_tick(self):
        if not hasattr(self, '_scanning') or not self._scanning:
            return
        c = self._scan_colors[self._scan_idx % len(self._scan_colors)]
        self.scan_bar.configure(bg=c)
        self._scan_idx += 1
        self._scan_anim_id = self.after(60, self._scan_tick)

    def _scan_stop(self):
        self._scanning = False
        if self._scan_anim_id:
            self.after_cancel(self._scan_anim_id)
            self._scan_anim_id = None
        self.scan_bar.configure(bg=BORDER)

    # ── Analyze ───────────────────────────────────────────────────────────────

    def _analyze(self):
        text = self.txt.get("1.0", "end-1c").strip()
        if not text or text == self._ph:
            messagebox.showwarning("No Input",
                                   "Paste an email before analyzing.", parent=self)
            return

        # Show scanning state
        self._scanning = True
        self._scan_start()
        self._update_status_tag("SCANNING...", CYAN)
        self.analyze_btn.configure(state="disabled", bg=MUTED)

        # Slight delay to let scan animation play one cycle before showing result
        self.after(480, lambda: self._run_analysis(text))

    def _run_analysis(self, text):
        self._scan_stop()
        self.analyze_btn.configure(state="normal", bg=BLUE)

        r = analyze_email(text)
        col, _, _ = VERDICT_CFG[r["verdict"]]

        # Verdict + state
        self.v_lbl.configure(text=r["verdict"], fg=col)
        self.st_lbl.configure(text=r["state"], fg=col)
        self._update_status_tag(r["verdict"], col)

        # Stats
        self.stat_kw.configure(text=str(r["total_kw"]), fg=col)
        self.stat_re.configure(text=str(len(r["re_hits"])), fg=col)
        self.stat_acc.configure(text="YES" if r["accepted"] else "NO",
                                fg=RED if r["accepted"] else GREEN)

        # Animated gauge
        self.gauge.animate_to(r["score"], col, r["verdict"])

        # Animated DFA traversal
        self.dfa.reset()
        self.after(200, lambda: self.dfa.traverse_to(r["state"]))

        # Detail log
        lines = [
            f"  Verdict       {r['verdict']}",
            f"  Spam Score    {r['score']}%",
            f"  DFA State     {r['state']}",
            f"  Accepted      {'Yes' if r['accepted'] else 'No'}",
            f"  Keyword Hits  {r['total_kw']}",
            "",
            "  ── Keyword Matches " + "─" * 31,
        ]
        if r["kw_hits"]:
            for cat, kws in r["kw_hits"].items():
                lines.append(f"\n  {cat}")
                lines += [f"    ·  {k}" for k in kws]
        else:
            lines.append("  None detected.")

        lines += ["", "  ── Regex Matches " + "─" * 33]
        lines += ([f"  ·  {lbl}  ×{n}" for lbl, n in r["re_hits"]]
                  if r["re_hits"] else ["  None detected."])

        lines += ["", "  ── DFA Path " + "─" * 37,
                  "  q0  →  q1  →  q2  →  q3",
                  f"  Halted at  {r['state']}"]

        self._set_detail("\n".join(lines))

    def _update_status_tag(self, text, color):
        # Rebuild tag label in place
        for w in self.status_tag.winfo_children():
            w.destroy()
        bg = self._TAG_BG.get(color, PANEL)
        self.status_tag.configure(bg=bg)
        tk.Label(self.status_tag, text=text,
                 font=("Segoe UI", 7, "bold"),
                 bg=bg, fg=color).pack()

    def _set_detail(self, txt):
        self.detail.configure(state="normal")
        self.detail.delete("1.0", "end")
        if txt:
            self.detail.insert("1.0", txt)
        self.detail.configure(state="disabled")


if __name__ == "__main__":
    App().mainloop()
