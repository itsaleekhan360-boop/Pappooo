import tkinter as tk
from tkinter import messagebox
import re
import math

# ══════════════════════════════════════════════════════════════════════════════
#  ANALYSIS ENGINE
# ══════════════════════════════════════════════════════════════════════════════

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
    (r"\$\d+",                              "Dollar amount mentioned"),
    (r"https?://\S+",                       "URL link detected"),
    (r"\b\d{10,}\b",                        "Long numeric string"),
    (r"(?i)\bfree\b",                       "Keyword: FREE"),
    (r"(?i)\bgift\b",                       "Keyword: GIFT"),
    (r"(?i)\boffer\b",                      "Keyword: OFFER"),
    (r"(?i)dear\s+(sir|madam|friend|user)", "Generic salutation"),
    (r"(?i)\bunsubscribe\b",                "Unsubscribe link present"),
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
    re_hits = [(lbl, n) for lbl, n in
               ((lbl, len(re.findall(pat, text))) for pat, lbl in REGEX_PATTERNS)
               if n > 0]
    state    = dfa.run(total_kw)
    accepted = (state == "q3")
    score    = min(int(((total_kw + len(re_hits) * 0.5) / 20) * 100), 100)
    if accepted and score < 70:
        score = 70
    verdict = ("SPAM" if (score >= 60 or accepted)
               else "SUSPICIOUS" if score >= 30 else "SAFE")
    return {
        "verdict": verdict, "score": score, "state": state,
        "accepted": accepted, "kw_hits": kw_hits,
        "total_kw": total_kw, "re_hits": re_hits,
    }


# ══════════════════════════════════════════════════════════════════════════════
#  DESIGN TOKENS
# ══════════════════════════════════════════════════════════════════════════════

BG      = "#0C0C0E"
SURF    = "#131316"
RAISED  = "#1C1C20"
BORDER  = "#28282E"
BORDER2 = "#343438"
BLUE    = "#0A84FF"
BLUE_D  = "#005FD1"
TEXT    = "#EFEFEF"
SUB     = "#8A8A8F"
MUTED   = "#3A3A40"

# Verdict palette — (foreground, dim-background, border)
V = {
    "SPAM":       ("#FF453A", "#1E0C0B", "#3D1412"),
    "SUSPICIOUS": ("#FF9F0A", "#1E160A", "#3D2C0C"),
    "SAFE":       ("#30D158", "#091A0F", "#0D3318"),
}

# DFA node ring colors
DFA_RING = {
    "q0": "#5E5CE6",  # indigo
    "q1": "#64D2FF",  # sky
    "q2": "#FF9F0A",  # amber
    "q3": "#FF453A",  # red
}

F10  = ("Segoe UI", 10)
F9   = ("Segoe UI",  9)
F8   = ("Segoe UI",  8)
MONO = ("Consolas",  9)
BOLD = ("Segoe UI", 10, "bold")
H1   = ("Segoe UI", 11, "bold")


# ══════════════════════════════════════════════════════════════════════════════
#  DFA STATE BAR  — bottom strip with animated node traversal
# ══════════════════════════════════════════════════════════════════════════════

class DFABar(tk.Canvas):
    """Horizontal animated DFA strip rendered at the bottom of the window."""

    NODES = ["q0", "q1", "q2", "q3"]
    NR    = 13          # node radius
    GAP   = 90          # gap between node centres
    W     = 4 * NR * 2 + 3 * GAP + 60
    H     = 52

    def __init__(self, parent, **kw):
        super().__init__(parent, width=self.W, height=self.H,
                         bg=SURF, highlightthickness=0, **kw)
        self._lit: set[str] = set()
        self._draw()

    # ── x-centre of node i ───────────────────────────────────────────────────
    def _nx(self, i: int) -> int:
        total = self.W
        span  = (len(self.NODES) - 1) * self.GAP
        start = (total - span) // 2
        return start + i * self.GAP

    def _draw(self):
        self.delete("all")
        cy = self.H // 2
        xs = [self._nx(i) for i in range(len(self.NODES))]

        # Connector lines between nodes
        for i in range(len(self.NODES) - 1):
            both = self.NODES[i] in self._lit and self.NODES[i+1] in self._lit
            col  = DFA_RING[self.NODES[i]] if both else BORDER2
            self.create_line(xs[i] + self.NR, cy, xs[i+1] - self.NR, cy,
                             fill=col, width=1)

        # Self-loop arc on q3
        x3 = xs[3]
        lit3 = "q3" in self._lit
        self.create_arc(x3 - self.NR - 2, cy - self.NR - 14,
                        x3 + self.NR + 2, cy - self.NR + 6,
                        start=20, extent=200, style="arc",
                        outline=DFA_RING["q3"] if lit3 else MUTED, width=1)

        # Nodes
        for i, sid in enumerate(self.NODES):
            x = xs[i]
            lit  = sid in self._lit
            ring = DFA_RING[sid]
            # Outer glow for accepting state q3
            if sid == "q3":
                self.create_oval(x - self.NR - 4, cy - self.NR - 4,
                                 x + self.NR + 4, cy + self.NR + 4,
                                 outline=ring if lit else MUTED,
                                 width=1, dash=(3, 3))
            fill = RAISED if lit else SURF
            self.create_oval(x - self.NR, cy - self.NR,
                             x + self.NR, cy + self.NR,
                             fill=fill,
                             outline=ring if lit else MUTED,
                             width=2 if lit else 1)
            self.create_text(x, cy,
                             text=sid, font=("Consolas", 8, "bold"),
                             fill=ring if lit else SUB)

        # State label on far right
        lbl = f"State: {max(self._lit, key=self.NODES.index)}" if self._lit else "State: —"
        self.create_text(self.W - 8, cy, text=lbl,
                         font=F8, fill=SUB, anchor="e")

    def traverse(self, final_state: str, step: int = 0):
        """Light nodes up one by one until final_state is reached."""
        idx = self.NODES.index(final_state)
        if step <= idx:
            self._lit = set(self.NODES[:step + 1])
            self._draw()
            self.after(230, lambda: self.traverse(final_state, step + 1))

    def reset(self):
        self._lit = set()
        self._draw()


# ══════════════════════════════════════════════════════════════════════════════
#  RESULT PANEL — right side, shows empty state or full analysis
# ══════════════════════════════════════════════════════════════════════════════

class ResultPanel(tk.Frame):
    """Right-hand panel. Switches between idle and result views."""

    def __init__(self, parent, **kw):
        super().__init__(parent, bg=BG, **kw)
        self._score_target = 0
        self._build_idle()

    # ── Idle / empty state ───────────────────────────────────────────────────

    def _build_idle(self):
        self._clear_children()
        wrapper = tk.Frame(self, bg=BG)
        wrapper.place(relx=0.5, rely=0.5, anchor="center")

        # Shield icon drawn with canvas
        c = tk.Canvas(wrapper, width=56, height=62,
                      bg=BG, highlightthickness=0)
        c.pack()
        # Body of shield
        pts = [28, 4,  52, 14,  52, 34,  28, 58,  4, 34,  4, 14]
        c.create_polygon(pts, outline=MUTED, fill="", width=2)
        # Inner checkmark placeholder
        c.create_text(28, 33, text="?", font=("Segoe UI", 18), fill=MUTED)

        tk.Label(wrapper, text="No analysis yet",
                 font=("Segoe UI", 13, "bold"), bg=BG, fg=SUB).pack(pady=(18, 4))
        tk.Label(wrapper, text="Paste an email on the left\nand click Analyze.",
                 font=F10, bg=BG, fg=MUTED, justify="center").pack()

    # ── Result view ──────────────────────────────────────────────────────────

    def show_result(self, r: dict):
        self._clear_children()
        fg, bg_dim, bdr = V[r["verdict"]]
        score = r["score"]

        # ── Hero: verdict + score ─────────────────────────────────────────
        hero = tk.Frame(self, bg=bg_dim, padx=24, pady=22)
        hero.pack(fill="x")

        top_row = tk.Frame(hero, bg=bg_dim)
        top_row.pack(fill="x")

        tk.Label(top_row, text=r["verdict"],
                 font=("Segoe UI", 42, "bold"),
                 bg=bg_dim, fg=fg).pack(side="left")

        # Score block on the right
        score_f = tk.Frame(top_row, bg=bg_dim)
        score_f.pack(side="right", anchor="s", pady=(10, 0))
        self._score_lbl = tk.Label(score_f, text="0%",
                                   font=("Segoe UI", 28, "bold"),
                                   bg=bg_dim, fg=fg)
        self._score_lbl.pack()
        tk.Label(score_f, text="spam score",
                 font=F8, bg=bg_dim, fg=fg).pack()

        # Subtitle
        subtitles = {
            "SPAM":       "High likelihood of spam. Do not engage.",
            "SUSPICIOUS": "Proceed with caution. Several indicators found.",
            "SAFE":       "No significant spam signals detected.",
        }
        tk.Label(hero, text=subtitles[r["verdict"]],
                 font=F10, bg=bg_dim, fg=fg).pack(anchor="w", pady=(6, 0))

        # ── Meta row: DFA state + keyword count ───────────────────────────
        meta = tk.Frame(self, bg=SURF, padx=24, pady=10)
        meta.pack(fill="x")
        tk.Frame(meta, bg=bdr, height=1).place(relx=0, rely=0, relwidth=1)

        for label, value, col in [
            ("DFA State",     r["state"],                      fg),
            ("Accepted",      "Yes" if r["accepted"] else "No", fg),
            ("Keyword hits",  str(r["total_kw"]),               TEXT),
            ("Pattern hits",  str(len(r["re_hits"])),           TEXT),
        ]:
            cell = tk.Frame(meta, bg=SURF)
            cell.pack(side="left", padx=(0, 32))
            tk.Label(cell, text=label.upper(),
                     font=("Segoe UI", 7), bg=SURF, fg=MUTED).pack(anchor="w")
            tk.Label(cell, text=value,
                     font=("Segoe UI", 12, "bold"), bg=SURF, fg=col).pack(anchor="w")

        # ── Findings scroll area ──────────────────────────────────────────
        scroll_f = tk.Frame(self, bg=BG)
        scroll_f.pack(fill="both", expand=True)

        canvas = tk.Canvas(scroll_f, bg=BG, highlightthickness=0,
                           yscrollcommand=lambda *a: vsb.set(*a))
        vsb = tk.Scrollbar(scroll_f, orient="vertical",
                           command=canvas.yview, width=8)
        vsb.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)

        inner = tk.Frame(canvas, bg=BG)
        win_id = canvas.create_window(0, 0, anchor="nw", window=inner)

        def _on_resize(e):
            canvas.itemconfig(win_id, width=e.width)
        canvas.bind("<Configure>", _on_resize)

        def _on_frame(e):
            canvas.configure(scrollregion=canvas.bbox("all"))
        inner.bind("<Configure>", _on_frame)

        canvas.bind_all("<MouseWheel>",
                        lambda e: canvas.yview_scroll(-1*(e.delta//120), "units"))

        pad = dict(padx=24, pady=0)

        # Keyword findings
        if r["kw_hits"]:
            self._section(inner, "KEYWORD MATCHES", **pad)
            for cat, kws in r["kw_hits"].items():
                self._finding_row(inner, cat, kws, fg, **pad)

        # Regex findings
        if r["re_hits"]:
            self._section(inner, "PATTERN MATCHES", pady=(16, 0), padx=24)
            for lbl, count in r["re_hits"]:
                self._regex_row(inner, lbl, count, **pad)

        tk.Frame(inner, bg=BG, height=20).pack()

        # Animate score
        self._animate_score(score, fg, bg_dim)

    # ── Sub-widgets ───────────────────────────────────────────────────────────

    def _section(self, parent, title, **kw):
        f = tk.Frame(parent, bg=BG)
        f.pack(fill="x", pady=(20, 6), **{k: v for k,v in kw.items()
                                           if k != "pady"})
        tk.Label(f, text=title, font=("Segoe UI", 8, "bold"),
                 bg=BG, fg=MUTED).pack(side="left")
        tk.Frame(f, bg=BORDER, height=1).pack(side="left", fill="x",
                                               expand=True, padx=(10, 0))

    def _finding_row(self, parent, category: str, kws: list, accent: str, **kw):
        row = tk.Frame(parent, bg=RAISED)
        row.pack(fill="x", pady=1, **{k: v for k,v in kw.items()
                                       if k != "pady"})
        row.configure(highlightbackground=BORDER, highlightthickness=1)

        inner = tk.Frame(row, bg=RAISED, padx=14, pady=10)
        inner.pack(fill="x")

        tk.Label(inner, text=category, font=BOLD,
                 bg=RAISED, fg=TEXT).pack(side="left", anchor="w")

        count_f = tk.Frame(inner, bg=MUTED, padx=6, pady=2)
        count_f.pack(side="right", anchor="center")
        tk.Label(count_f, text=str(len(kws)),
                 font=("Segoe UI", 8, "bold"), bg=MUTED, fg=TEXT).pack()

        # Keyword chips
        chips_f = tk.Frame(row, bg=RAISED, padx=14)
        chips_f.pack(fill="x", pady=(0, 10))

        chip_row = tk.Frame(chips_f, bg=RAISED)
        chip_row.pack(anchor="w")
        for kw_text in kws[:6]:
            chip = tk.Frame(chip_row, bg=SURF, padx=7, pady=3)
            chip.pack(side="left", padx=(0, 5))
            tk.Label(chip, text=kw_text, font=("Segoe UI", 8),
                     bg=SURF, fg=SUB).pack()
        if len(kws) > 6:
            tk.Label(chip_row, text=f"+{len(kws)-6} more",
                     font=F8, bg=RAISED, fg=MUTED).pack(side="left", padx=4)

    def _regex_row(self, parent, label: str, count: int, **kw):
        row = tk.Frame(parent, bg=SURF, pady=0)
        row.pack(fill="x", pady=1, **{k: v for k,v in kw.items()
                                       if k != "pady"})
        inner = tk.Frame(row, bg=SURF, padx=14, pady=9)
        inner.pack(fill="x")
        tk.Label(inner, text=label, font=F10,
                 bg=SURF, fg=TEXT).pack(side="left")
        tk.Label(inner, text=f"×{count}", font=("Consolas", 9, "bold"),
                 bg=SURF, fg=SUB).pack(side="right")

    def _animate_score(self, target: int, fg: str, bg: str, step: int = 0):
        frames = 36
        if step > frames:
            return
        t = step / frames
        eased = 1 - (1 - t) ** 3
        self._score_lbl.configure(text=f"{int(target * eased)}%", fg=fg, bg=bg)
        if step < frames:
            self.after(16, lambda: self._animate_score(target, fg, bg, step + 1))

    # ─────────────────────────────────────────────────────────────────────────

    def _clear_children(self):
        for w in self.winfo_children():
            w.destroy()


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN APPLICATION
# ══════════════════════════════════════════════════════════════════════════════

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("SpamGuard — Theory of Automata | IQRA University")
        self.configure(bg=BG)
        self.geometry("1140x700")
        self.minsize(960, 580)
        self._build()

    # ── Layout ────────────────────────────────────────────────────────────────

    def _build(self):
        self._nav()
        self._body()
        self._footer()

    def _nav(self):
        bar = tk.Frame(self, bg=SURF, height=46)
        bar.pack(fill="x")
        bar.pack_propagate(False)
        tk.Frame(self, bg=BORDER, height=1).pack(fill="x")

        inner = tk.Frame(bar, bg=SURF)
        inner.pack(fill="both", expand=True, padx=24)

        tk.Label(inner, text="SpamGuard",
                 font=("Segoe UI", 12, "bold"), bg=SURF, fg=TEXT).pack(
                     side="left", pady=12)
        tk.Label(inner, text="  /  Theory of Automata",
                 font=F10, bg=SURF, fg=MUTED).pack(side="left", pady=12)

        tk.Label(inner, text="IQRA University  ·  DFA + Regex Engine",
                 font=F8, bg=SURF, fg=MUTED).pack(side="right", pady=16)

    def _body(self):
        body = tk.Frame(self, bg=BG)
        body.pack(fill="both", expand=True)

        # ── Left: email input ─────────────────────────────────────────────
        left = tk.Frame(body, bg=BG, width=500)
        left.pack(side="left", fill="both", expand=True)
        left.pack_propagate(False)

        # Vertical right border
        tk.Frame(body, bg=BORDER, width=1).pack(side="left", fill="y")

        # ── Right: result panel ───────────────────────────────────────────
        self.result = ResultPanel(body)
        self.result.pack(side="left", fill="both", expand=True)

        self._build_input(left)

    def _build_input(self, parent):
        pad = dict(padx=24)

        # Label row
        label_row = tk.Frame(parent, bg=BG)
        label_row.pack(fill="x", padx=24, pady=(20, 8))
        tk.Label(label_row, text="EMAIL CONTENT",
                 font=("Segoe UI", 8, "bold"), bg=BG, fg=MUTED).pack(side="left")

        # Textarea with focus-border trick using a wrapper frame
        border_wrap = tk.Frame(parent, bg=BORDER, padx=1, pady=1)
        border_wrap.pack(fill="both", expand=True, **pad)

        self.txt = tk.Text(
            border_wrap, wrap="word", font=MONO,
            bg=SURF, fg=TEXT, insertbackground=BLUE,
            selectbackground=BORDER, selectforeground=TEXT,
            relief="flat", borderwidth=0, padx=16, pady=14,
            spacing1=2, spacing3=2)
        self.txt.pack(fill="both", expand=True)

        self.txt.bind("<FocusIn>",
                      lambda e: border_wrap.configure(bg=BLUE))
        self.txt.bind("<FocusOut>",
                      lambda e: border_wrap.configure(bg=BORDER))

        self._ph = "Paste the full email body here..."
        self.txt.insert("1.0", self._ph)
        self.txt.configure(fg=MUTED)
        self.txt.bind("<FocusIn>",  self._ph_clear,  add="+")
        self.txt.bind("<FocusOut>", self._ph_restore, add="+")

        # ── Scan pulse bar ────────────────────────────────────────────────
        self._scan_bar = tk.Frame(parent, bg=BORDER, height=2)
        self._scan_bar.pack(fill="x", **pad)
        self._scanning = False

        # ── Action buttons ────────────────────────────────────────────────
        btn_row = tk.Frame(parent, bg=BG)
        btn_row.pack(fill="x", padx=24, pady=14)

        self.analyze_btn = tk.Button(
            btn_row, text="Analyze", command=self._analyze,
            font=("Segoe UI", 10, "bold"),
            bg=BLUE, fg="white", activebackground=BLUE_D,
            activeforeground="white", relief="flat",
            cursor="hand2", padx=20, pady=8, bd=0)
        self.analyze_btn.pack(side="left")

        for label, cmd in [("Spam sample", self._load_spam),
                            ("Safe sample", self._load_safe)]:
            tk.Button(btn_row, text=label, command=cmd,
                      font=F10, bg=RAISED, fg=SUB,
                      activebackground=BORDER, activeforeground=TEXT,
                      relief="flat", cursor="hand2",
                      padx=14, pady=8, bd=0,
                      highlightbackground=BORDER,
                      highlightthickness=1).pack(side="left", padx=(8, 0))

        tk.Button(btn_row, text="Clear", command=self._clear,
                  font=F10, bg=BG, fg=MUTED,
                  activebackground=BG, activeforeground=SUB,
                  relief="flat", cursor="hand2",
                  padx=14, pady=8, bd=0).pack(side="right")

    def _footer(self):
        tk.Frame(self, bg=BORDER, height=1).pack(fill="x")
        foot = tk.Frame(self, bg=SURF, height=52)
        foot.pack(fill="x")
        foot.pack_propagate(False)

        self.dfa_bar = DFABar(foot)
        self.dfa_bar.pack(side="left", padx=24, pady=6)

        credits = tk.Frame(foot, bg=SURF)
        credits.pack(side="right", padx=24)
        tk.Label(credits,
                 text="Moniza Fatima  ·  Laraib Suikarno  ·  Miss Alisha Farmaan",
                 font=F8, bg=SURF, fg=MUTED).pack(anchor="e")

    # ── Placeholder ───────────────────────────────────────────────────────────

    def _ph_clear(self, _=None):
        if self.txt.get("1.0", "end-1c") == self._ph:
            self.txt.delete("1.0", "end")
            self.txt.configure(fg=TEXT)

    def _ph_restore(self, _=None):
        if not self.txt.get("1.0", "end-1c").strip():
            self.txt.insert("1.0", self._ph)
            self.txt.configure(fg=MUTED)

    # ── Sample loaders ────────────────────────────────────────────────────────

    def _load_spam(self):
        self._set_text(
            "DEAR USER!! You have WON a $1,000,000 LOTTERY PRIZE!\n"
            "Click here to CLAIM NOW and verify your account immediately.\n"
            "LIMITED TIME offer – ACT NOW before it expires!\n"
            "Download now FREE software to activate your reward.\n"
            "Wire transfer details required. Respond immediately.\n"
            "Visit: https://claim-prize.free.net/verify?id=12345678901234\n"
            "Unsubscribe | Risk free trial | 100% Safe Guaranteed!!"
        )

    def _load_safe(self):
        self._set_text(
            "Hi Alex,\n\n"
            "I hope you're doing well. Please find attached the meeting notes "
            "from yesterday's discussion. Let me know if you have any questions.\n\n"
            "The team meeting is scheduled for Thursday at 3 PM in conference room B. "
            "Please bring your laptop and the quarterly report.\n\n"
            "Best regards,\nSarah\nProject Manager"
        )

    def _set_text(self, txt: str):
        self.txt.configure(fg=TEXT)
        self.txt.delete("1.0", "end")
        self.txt.insert("1.0", txt)

    # ── Clear ─────────────────────────────────────────────────────────────────

    def _clear(self):
        self.txt.delete("1.0", "end")
        self._ph_restore()
        self.result._build_idle()
        self.dfa_bar.reset()

    # ── Scan animation ────────────────────────────────────────────────────────

    def _scan_tick(self, idx: int = 0):
        if not self._scanning:
            return
        colors = [BLUE, "#005FD1", "#003D99", BORDER, BORDER, BLUE]
        self._scan_bar.configure(bg=colors[idx % len(colors)])
        self.after(55, lambda: self._scan_tick(idx + 1))

    # ── Core: analyze ─────────────────────────────────────────────────────────

    def _analyze(self):
        text = self.txt.get("1.0", "end-1c").strip()
        if not text or text == self._ph:
            messagebox.showwarning("Empty input",
                                   "Paste an email body first.", parent=self)
            return

        # Start scan feedback
        self._scanning = True
        self.analyze_btn.configure(state="disabled", bg=MUTED,
                                   text="Analyzing…")
        self._scan_tick()

        self.after(500, lambda: self._finish(text))

    def _finish(self, text: str):
        self._scanning = False
        self._scan_bar.configure(bg=BORDER)
        self.analyze_btn.configure(state="normal", bg=BLUE, text="Analyze")

        r = analyze_email(text)
        self.result.show_result(r)
        self.dfa_bar.reset()
        self.after(200, lambda: self.dfa_bar.traverse(r["state"]))


if __name__ == "__main__":
    App().mainloop()
