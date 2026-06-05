"""
SpamGuard — Theory of Automata | IQRA University
DFA + Regex-based spam email classifier
"""
import tkinter as tk
from tkinter import messagebox
import re, math

# ══════════════════════════════════════════════════════════════════════════════
#  ENGINE
# ══════════════════════════════════════════════════════════════════════════════

SPAM_KEYWORDS = {
    "Financial Scam": [
        "free money","you won","prize","lottery","claim now","bank account",
        "wire transfer","cash prize","million dollars","inheritance",
        "winner","jackpot","earn money fast",
    ],
    "Phishing": [
        "verify your account","click here","update your password",
        "confirm your email","login now","suspended account",
        "unusual activity","unauthorized access","reset your password",
        "your account has been","verify immediately",
    ],
    "Malware": [
        "download now","free software","crack version","keygen",
        "activate now","serial key","patch download",
    ],
    "Urgency": [
        "act now","limited time","expires soon","urgent","last chance",
        "do not ignore","immediate action","respond immediately","deadline today",
    ],
    "Adult Content": [
        "adult content","18+","hot singles","meet girls","dating site","explicit content",
    ],
    "Fake Health": [
        "lose weight fast","miracle cure","diet pill","guaranteed results",
        "risk free trial","100% safe","doctors hate","slim fast",
    ],
}

REGEX_PATTERNS = [
    (r"\b[A-Z]{4,}\b",                     "ALL-CAPS words"),
    (r"!{2,}",                              "Multiple exclamation marks"),
    (r"\$\d+",                              "Dollar amount"),
    (r"https?://\S+",                       "URL link"),
    (r"\b\d{10,}\b",                        "Long number string"),
    (r"(?i)\bfree\b",                       "Word: free"),
    (r"(?i)\bgift\b",                       "Word: gift"),
    (r"(?i)\boffer\b",                      "Word: offer"),
    (r"(?i)dear\s+(sir|madam|friend|user)", "Generic salutation"),
    (r"(?i)\bunsubscribe\b",                "Unsubscribe link"),
]


class SpamDFA:
    T = {
        ("q0",0):"q0", ("q0",1):"q1",
        ("q1",1):"q1", ("q1",2):"q2",
        ("q2",1):"q2", ("q2",2):"q3",
        ("q3",1):"q3", ("q3",2):"q3",
    }
    def run(self, n: int) -> str:
        s, r = "q0", n
        while r > 0:
            step = min(r, 2)
            s = self.T.get((s, step), s)
            r -= step
        return s


def analyze(text: str) -> dict:
    tl = text.lower()
    dfa = SpamDFA()
    kw, nkw = {}, 0
    for cat, words in SPAM_KEYWORDS.items():
        found = [w for w in words if w in tl]
        if found:
            kw[cat] = found
            nkw += len(found)
    rx = [(lbl, n) for lbl, n in
          ((lbl, len(re.findall(p, text))) for p, lbl in REGEX_PATTERNS) if n]
    state    = dfa.run(nkw)
    accepted = state == "q3"
    score    = min(int(((nkw + len(rx) * 0.5) / 20) * 100), 100)
    if accepted and score < 70:
        score = 70
    verdict = ("SPAM" if score >= 60 or accepted
               else "SUSPICIOUS" if score >= 30 else "SAFE")
    return dict(verdict=verdict, score=score, state=state,
                accepted=accepted, kw=kw, nkw=nkw, rx=rx)


# ══════════════════════════════════════════════════════════════════════════════
#  DESIGN  —  Raycast-inspired, 8px grid, Inter-weight hierarchy
# ══════════════════════════════════════════════════════════════════════════════

# Palette
C = {
    "canvas":  "#07080A",   # Raycast canvas
    "bg":      "#0D0E10",   # page bg
    "surface": "#131418",   # cards / panels
    "raised":  "#1A1B20",   # slightly elevated
    "border":  "#26272E",   # subtle dividers
    "border2": "#32333C",   # stronger divider
    "accent":  "#5865F2",   # indigo (Linear/Discord blue)
    "accent_d":"#4752C4",
    "text":    "#E8E9EE",   # primary text
    "dim":     "#888A96",   # secondary
    "muted":   "#404150",   # placeholder / muted
    # verdict
    "red":     "#F04747",
    "amber":   "#FAA61A",
    "green":   "#3BA55D",
    "red_bg":  "#1A0F0F",
    "amber_bg":"#1A1508",
    "green_bg":"#0C1A10",
    "red_dim": "#3D1A1A",
    "amber_dim":"#3D2F10",
    "green_dim":"#1A3D24",
}

# Typography — weight does the work, not size jumps
T = {
    "ui":       ("Segoe UI",  10),
    "ui_b":     ("Segoe UI",  10, "bold"),
    "sm":       ("Segoe UI",   9),
    "xs":       ("Segoe UI",   8),
    "label":    ("Segoe UI",   8, "bold"),
    "mono":     ("Consolas",   9),
    "h2":       ("Segoe UI",  12, "bold"),
    "verdict":  ("Segoe UI",  32, "bold"),
    "score":    ("Segoe UI",  22, "bold"),
    "nav":      ("Segoe UI",  11, "bold"),
}

# Verdict config
V = {
    "SPAM":       ("red",   "red_bg",   "red_dim"),
    "SUSPICIOUS": ("amber", "amber_bg", "amber_dim"),
    "SAFE":       ("green", "green_bg", "green_dim"),
}


# ══════════════════════════════════════════════════════════════════════════════
#  COMPONENTS
# ══════════════════════════════════════════════════════════════════════════════

class DFAStrip(tk.Canvas):
    """Footer DFA state machine — nodes animate left-to-right on analysis."""
    NODES = ["q0", "q1", "q2", "q3"]
    NR = 12; GAP = 88; H = 48

    # Node ring colors
    NC = {"q0": "#5865F2", "q1": "#00B0F4", "q2": "#FAA61A", "q3": "#F04747"}

    def __init__(self, parent, **kw):
        w = len(self.NODES) * self.NR * 2 + (len(self.NODES)-1) * self.GAP + 80
        super().__init__(parent, width=w, height=self.H,
                         bg=C["surface"], highlightthickness=0, **kw)
        self._lit: set = set()
        self._redraw()

    def _cx(self, i):
        span  = (len(self.NODES)-1) * self.GAP
        start = (self.winfo_reqwidth() - span) // 2
        return start + i * self.GAP

    def _redraw(self):
        self.delete("all")
        cy = self.H // 2
        xs = [self._cx(i) for i in range(4)]

        for i in range(3):
            lit = self.NODES[i] in self._lit and self.NODES[i+1] in self._lit
            self.create_line(xs[i]+self.NR, cy, xs[i+1]-self.NR, cy,
                             fill=self.NC[self.NODES[i]] if lit else C["border2"],
                             width=1)
        # Self-loop on q3
        x3, r = xs[3], self.NR
        lit3 = "q3" in self._lit
        self.create_arc(x3-r-2, cy-r-12, x3+r+2, cy-r+4,
                        start=20, extent=200, style="arc",
                        outline=self.NC["q3"] if lit3 else C["muted"], width=1)

        for i, s in enumerate(self.NODES):
            x   = xs[i]
            lit = s in self._lit
            nc  = self.NC[s]
            if s == "q3":
                self.create_oval(x-r-4, cy-r-4, x+r+4, cy+r+4,
                                 outline=nc if lit else C["muted"],
                                 width=1, dash=(3,3))
            bg = C["raised"] if lit else C["surface"]
            self.create_oval(x-r, cy-r, x+r, cy+r,
                             fill=bg, outline=nc if lit else C["muted"],
                             width=2 if lit else 1)
            self.create_text(x, cy, text=s, font=("Consolas", 8, "bold"),
                             fill=nc if lit else C["dim"])

        # Current state label
        cur = (max(self._lit, key=lambda s: self.NODES.index(s))
               if self._lit else None)
        lbl = f"state  {cur}" if cur else "state  —"
        rx = self.winfo_reqwidth() - 8
        self.create_text(rx, cy, text=lbl, font=("Consolas", 8),
                         fill=C["dim"], anchor="e")

    def animate(self, final: str, step: int = 0):
        idx = self.NODES.index(final)
        if step <= idx:
            self._lit = set(self.NODES[:step+1])
            self._redraw()
            self.after(240, lambda: self.animate(final, step+1))

    def reset(self):
        self._lit = set()
        self._redraw()


def _hline(parent, bg=None, pady=0):
    """1-px horizontal divider."""
    tk.Frame(parent, bg=bg or C["border"], height=1).pack(
        fill="x", pady=pady)


def _label(parent, text, style="ui", color="dim", bg=None, **kw):
    return tk.Label(parent, text=text, font=T[style],
                    bg=bg or C["surface"], fg=C[color], **kw)


# ══════════════════════════════════════════════════════════════════════════════
#  RESULT PANEL
# ══════════════════════════════════════════════════════════════════════════════

class ResultPanel(tk.Frame):
    def __init__(self, parent, **kw):
        super().__init__(parent, bg=C["bg"], **kw)
        self._show_idle()

    # ── Idle state ────────────────────────────────────────────────────────────
    def _show_idle(self):
        self._clear()
        w = tk.Frame(self, bg=C["bg"])
        w.place(relx=.5, rely=.42, anchor="center")

        # Minimal shield outline
        cv = tk.Canvas(w, width=40, height=46, bg=C["bg"], highlightthickness=0)
        cv.pack()
        pts = [20,3, 38,11, 38,28, 20,43, 2,28, 2,11]
        cv.create_polygon(pts, outline=C["muted"], fill="", width=1.5)
        cv.create_text(20,26, text="?", font=("Segoe UI",14), fill=C["muted"])

        tk.Label(w, text="No analysis", font=T["h2"],
                 bg=C["bg"], fg=C["dim"]).pack(pady=(16,4))
        tk.Label(w, text="Paste an email and click Analyze",
                 font=T["sm"], bg=C["bg"], fg=C["muted"]).pack()

        # Show what we detect — useful context, not just filler
        cats_f = tk.Frame(self, bg=C["bg"])
        cats_f.place(relx=.5, rely=.72, anchor="center")
        tk.Label(cats_f, text="DETECTS",
                 font=T["label"], bg=C["bg"], fg=C["muted"]).pack()
        row1 = tk.Frame(cats_f, bg=C["bg"])
        row1.pack(pady=(6,0))
        for cat in list(SPAM_KEYWORDS.keys())[:3]:
            chip = tk.Frame(row1, bg=C["raised"])
            chip.pack(side="left", padx=3)
            tk.Label(chip, text=cat, font=T["xs"],
                     bg=C["raised"], fg=C["dim"],
                     padx=8, pady=4).pack()
        row2 = tk.Frame(cats_f, bg=C["bg"])
        row2.pack(pady=(4,0))
        for cat in list(SPAM_KEYWORDS.keys())[3:]:
            chip = tk.Frame(row2, bg=C["raised"])
            chip.pack(side="left", padx=3)
            tk.Label(chip, text=cat, font=T["xs"],
                     bg=C["raised"], fg=C["dim"],
                     padx=8, pady=4).pack()

    # ── Result state ──────────────────────────────────────────────────────────
    def show(self, r: dict):
        self._clear()
        fg_k, bg_k, dim_k = V[r["verdict"]]
        fg  = C[fg_k]
        rbg = C[bg_k]
        rdim = C[dim_k]

        # ── Verdict hero row ──────────────────────────────────────────────
        hero = tk.Frame(self, bg=rbg, padx=24, pady=20)
        hero.pack(fill="x")

        left_h = tk.Frame(hero, bg=rbg)
        left_h.pack(side="left", fill="y")

        # Status dot + verdict text
        dot_row = tk.Frame(left_h, bg=rbg)
        dot_row.pack(anchor="w")
        cv = tk.Canvas(dot_row, width=10, height=10,
                       bg=rbg, highlightthickness=0)
        cv.pack(side="left", padx=(0,8), pady=4)
        cv.create_oval(0,0,10,10, fill=fg, outline="")
        tk.Label(dot_row, text=r["verdict"], font=T["verdict"],
                 bg=rbg, fg=fg).pack(side="left")

        # Subtitle
        subs = {
            "SPAM": "High likelihood — do not interact.",
            "SUSPICIOUS": "Caution advised — review carefully.",
            "SAFE": "No significant signals detected.",
        }
        tk.Label(left_h, text=subs[r["verdict"]],
                 font=T["sm"], bg=rbg, fg=fg).pack(anchor="w", pady=(4,0))

        # Score on the right
        right_h = tk.Frame(hero, bg=rbg)
        right_h.pack(side="right", anchor="center")
        self._score_lbl = tk.Label(right_h, text="0%",
                                   font=T["score"], bg=rbg, fg=fg)
        self._score_lbl.pack()
        tk.Label(right_h, text="spam score",
                 font=T["xs"], bg=rbg, fg=fg).pack()

        # Bottom accent line on hero
        tk.Frame(self, bg=rdim, height=1).pack(fill="x")

        # ── Meta bar ─────────────────────────────────────────────────────
        meta = tk.Frame(self, bg=C["surface"], padx=24, pady=10)
        meta.pack(fill="x")

        cells = [
            ("DFA STATE",    r["state"],                          fg_k),
            ("ACCEPTED",     "Yes" if r["accepted"] else "No",    fg_k),
            ("KW SIGNALS",   str(r["nkw"]),                       "text"),
            ("PATTERNS",     str(len(r["rx"])),                   "text"),
        ]
        for i, (lbl, val, vc) in enumerate(cells):
            cell = tk.Frame(meta, bg=C["surface"])
            cell.pack(side="left", padx=(0, 28))
            tk.Label(cell, text=lbl, font=T["label"],
                     bg=C["surface"], fg=C["muted"]).pack(anchor="w")
            tk.Label(cell, text=val, font=("Segoe UI",13,"bold"),
                     bg=C["surface"], fg=C[vc]).pack(anchor="w", pady=(2,0))

        _hline(self, bg=C["border"])

        # ── Scrollable findings ───────────────────────────────────────────
        outer = tk.Frame(self, bg=C["bg"])
        outer.pack(fill="both", expand=True)

        cv2 = tk.Canvas(outer, bg=C["bg"], highlightthickness=0,
                        yscrollcommand=lambda *a: sb.set(*a))
        sb  = tk.Scrollbar(outer, orient="vertical",
                           command=cv2.yview, width=6)
        sb.pack(side="right", fill="y")
        cv2.pack(side="left", fill="both", expand=True)

        inner = tk.Frame(cv2, bg=C["bg"])
        wid   = cv2.create_window(0, 0, anchor="nw", window=inner)
        cv2.bind("<Configure>", lambda e: cv2.itemconfig(wid, width=e.width))
        inner.bind("<Configure>",
                   lambda e: cv2.configure(scrollregion=cv2.bbox("all")))
        cv2.bind_all("<MouseWheel>",
                     lambda e: cv2.yview_scroll(-(e.delta//120), "units"))

        px = dict(padx=24)

        # Keyword section
        if r["kw"]:
            self._section_head(inner, "KEYWORD SIGNALS", r["nkw"], **px)
            for cat, words in r["kw"].items():
                self._kw_row(inner, cat, words, fg, **px)

        # Regex section
        if r["rx"]:
            self._section_head(inner, "PATTERN SIGNALS",
                               sum(n for _, n in r["rx"]),
                               pady=(20, 0), **px)
            for label, n in r["rx"]:
                self._rx_row(inner, label, n, **px)

        tk.Frame(inner, bg=C["bg"], height=24).pack()

        # Start score animation
        self._animate(r["score"], fg, rbg)

    # ── Sub-components ────────────────────────────────────────────────────────

    def _section_head(self, p, title, count, pady=(16,0), **kw):
        f = tk.Frame(p, bg=C["bg"])
        f.pack(fill="x", pady=pady, **kw)
        tk.Label(f, text=title, font=T["label"],
                 bg=C["bg"], fg=C["muted"]).pack(side="left")
        tk.Label(f, text=str(count), font=T["label"],
                 bg=C["bg"], fg=C["dim"]).pack(side="right")
        tk.Frame(f, bg=C["border"], height=1).pack(
            side="bottom", fill="x", pady=(6,0))

    def _kw_row(self, p, category, words, accent, **kw):
        # Outer row container
        row = tk.Frame(p, bg=C["surface"],
                       highlightbackground=C["border"],
                       highlightthickness=1)
        row.pack(fill="x", pady=(0,1), **kw)

        top = tk.Frame(row, bg=C["surface"], padx=12, pady=9)
        top.pack(fill="x")

        # Category name
        tk.Label(top, text=category, font=T["ui_b"],
                 bg=C["surface"], fg=C["text"]).pack(side="left", anchor="w")

        # Count pill
        pill = tk.Frame(top, bg=C["raised"], padx=7, pady=2)
        pill.pack(side="right", anchor="center")
        tk.Label(pill, text=str(len(words)), font=T["xs"],
                 bg=C["raised"], fg=C["dim"]).pack()

        # Words as a single muted line (not chips — cleaner)
        words_str = "  ·  ".join(words[:5])
        if len(words) > 5:
            words_str += f"  +{len(words)-5}"
        bot = tk.Frame(row, bg=C["surface"], padx=12)
        bot.pack(fill="x")
        tk.Label(bot, text=words_str, font=T["mono"],
                 bg=C["surface"], fg=C["muted"],
                 anchor="w").pack(fill="x", pady=(0,8))

    def _rx_row(self, p, label, n, **kw):
        row = tk.Frame(p, bg=C["surface"],
                       highlightbackground=C["border"],
                       highlightthickness=1)
        row.pack(fill="x", pady=(0,1), **kw)
        inner = tk.Frame(row, bg=C["surface"], padx=12, pady=9)
        inner.pack(fill="x")
        tk.Label(inner, text=label, font=T["ui"],
                 bg=C["surface"], fg=C["text"]).pack(side="left")
        tk.Label(inner, text=f"×{n}", font=T["mono"],
                 bg=C["surface"], fg=C["dim"]).pack(side="right")

    def _animate(self, target, fg, bg, step=0, frames=40):
        t = 1 - (1 - step/frames)**3
        self._score_lbl.configure(text=f"{int(target*t)}%", fg=fg, bg=bg)
        if step < frames:
            self.after(14, lambda: self._animate(target, fg, bg, step+1, frames))

    def _clear(self):
        for w in self.winfo_children():
            w.destroy()


# ══════════════════════════════════════════════════════════════════════════════
#  APPLICATION
# ══════════════════════════════════════════════════════════════════════════════

class App(tk.Tk):
    PH = "Paste the full email body here…"

    def __init__(self):
        super().__init__()
        self.title("SpamGuard — Theory of Automata  |  IQRA University")
        self.configure(bg=C["canvas"])
        self.geometry("1160x700")
        self.minsize(960, 580)
        self._scanning = False
        self._build()

    # ── Build ─────────────────────────────────────────────────────────────────

    def _build(self):
        self._nav()
        self._main()
        self._footer()

    def _nav(self):
        bar = tk.Frame(self, bg=C["surface"], height=44)
        bar.pack(fill="x")
        bar.pack_propagate(False)
        _hline(self, bg=C["border"])

        f = tk.Frame(bar, bg=C["surface"])
        f.pack(fill="both", expand=True, padx=24)

        # Logo
        logo = tk.Frame(f, bg=C["surface"])
        logo.pack(side="left", pady=10)
        # Accent dot
        dot = tk.Canvas(logo, width=7, height=7,
                        bg=C["surface"], highlightthickness=0)
        dot.pack(side="left", padx=(0,8))
        dot.create_oval(0,0,7,7, fill=C["accent"], outline="")
        self._dot = dot
        self._dot_state = True
        self._pulse()

        tk.Label(logo, text="SpamGuard",
                 font=T["nav"], bg=C["surface"], fg=C["text"]).pack(side="left")
        tk.Label(logo, text="  /  Theory of Automata",
                 font=T["ui"], bg=C["surface"], fg=C["dim"]).pack(side="left")

        tk.Label(f, text="IQRA University  ·  DFA + Regex",
                 font=T["xs"], bg=C["surface"], fg=C["muted"]).pack(
                     side="right", pady=15)

    def _pulse(self):
        """Subtle breathing dot in nav."""
        self._dot_state = not self._dot_state
        col = C["accent"] if self._dot_state else C["accent_d"]
        self._dot.delete("all")
        self._dot.create_oval(0,0,7,7, fill=col, outline="")
        self.after(900, self._pulse)

    def _main(self):
        body = tk.Frame(self, bg=C["bg"])
        body.pack(fill="both", expand=True)

        # Input side (fixed 480px)
        left = tk.Frame(body, bg=C["bg"], width=480)
        left.pack(side="left", fill="y")
        left.pack_propagate(False)
        _hline(body, bg=C["border"])   # vertical — actually horizontal, use Frame trick

        # Actual vertical border
        vline = tk.Frame(body, bg=C["border"], width=1)
        vline.pack(side="left", fill="y")

        # Result side (fills rest)
        self.result = ResultPanel(body)
        self.result.pack(side="left", fill="both", expand=True)

        self._build_input(left)

    def _build_input(self, parent):
        # Top label
        lrow = tk.Frame(parent, bg=C["bg"])
        lrow.pack(fill="x", padx=24, pady=(20,8))
        tk.Label(lrow, text="EMAIL BODY", font=T["label"],
                 bg=C["bg"], fg=C["muted"]).pack(side="left")

        # Textarea — borderless, flush to surface
        self._border_f = tk.Frame(parent, bg=C["border"], padx=1, pady=1)
        self._border_f.pack(fill="both", expand=True, padx=24)

        self.txt = tk.Text(
            self._border_f, wrap="word", font=T["mono"],
            bg=C["surface"], fg=C["text"],
            insertbackground=C["accent"],
            selectbackground=C["border2"],
            selectforeground=C["text"],
            relief="flat", borderwidth=0,
            padx=16, pady=14, spacing1=3, spacing3=3,
            undo=True)
        self.txt.pack(fill="both", expand=True)
        self.txt.insert("1.0", self.PH)
        self.txt.configure(fg=C["muted"])

        self.txt.bind("<FocusIn>",
                      lambda e: [self._ph_clear(),
                                 self._border_f.configure(bg=C["accent"])])
        self.txt.bind("<FocusOut>",
                      lambda e: [self._ph_restore(),
                                 self._border_f.configure(bg=C["border"])])

        # Scan bar (2px, sits below textarea)
        self._scan = tk.Frame(parent, bg=C["border"], height=2)
        self._scan.pack(fill="x", padx=24)

        # Action row
        actions = tk.Frame(parent, bg=C["bg"])
        actions.pack(fill="x", padx=24, pady=16)

        self.btn = tk.Button(
            actions, text="Analyze", command=self._run,
            font=T["ui_b"], bg=C["accent"], fg="white",
            activebackground=C["accent_d"], activeforeground="white",
            relief="flat", cursor="hand2", padx=20, pady=8, bd=0)
        self.btn.pack(side="left")

        for label, cmd in [("Spam sample", self._sample_spam),
                            ("Safe sample", self._sample_safe)]:
            b = tk.Button(
                actions, text=label, command=cmd,
                font=T["ui"], bg=C["raised"], fg=C["dim"],
                activebackground=C["border2"], activeforeground=C["text"],
                relief="flat", cursor="hand2", padx=14, pady=8, bd=0,
                highlightbackground=C["border"], highlightthickness=1)
            b.pack(side="left", padx=(8,0))

        tk.Button(
            actions, text="Clear", command=self._clear,
            font=T["ui"], bg=C["bg"], fg=C["muted"],
            activebackground=C["bg"], activeforeground=C["dim"],
            relief="flat", cursor="hand2",
            padx=12, pady=8, bd=0).pack(side="right")

    def _footer(self):
        _hline(self, bg=C["border"])
        foot = tk.Frame(self, bg=C["surface"], height=48)
        foot.pack(fill="x")
        foot.pack_propagate(False)

        inner = tk.Frame(foot, bg=C["surface"])
        inner.pack(fill="both", expand=True, padx=24)

        self.dfa = DFAStrip(inner)
        self.dfa.pack(side="left", pady=6)

        tk.Label(inner,
                 text="Moniza Fatima  ·  Laraib Suikarno  ·  Miss Alisha Farmaan",
                 font=T["xs"], bg=C["surface"], fg=C["muted"]).pack(
                     side="right", pady=16)

    # ── Placeholder ───────────────────────────────────────────────────────────

    def _ph_clear(self):
        if self.txt.get("1.0","end-1c") == self.PH:
            self.txt.delete("1.0","end")
            self.txt.configure(fg=C["text"])

    def _ph_restore(self):
        if not self.txt.get("1.0","end-1c").strip():
            self.txt.insert("1.0", self.PH)
            self.txt.configure(fg=C["muted"])

    # ── Samples ───────────────────────────────────────────────────────────────

    def _sample_spam(self):
        self._set("DEAR USER!! You have WON a $1,000,000 LOTTERY PRIZE!\n"
                  "Click here to CLAIM NOW and verify your account immediately.\n"
                  "LIMITED TIME offer – ACT NOW before it expires!\n"
                  "Download now FREE software to activate your reward.\n"
                  "Wire transfer details required. Respond immediately.\n"
                  "Visit: https://claim-prize.free.net/verify?id=12345678901234\n"
                  "Unsubscribe | Risk free trial | 100% Safe Guaranteed!!")

    def _sample_safe(self):
        self._set("Hi Alex,\n\n"
                  "I hope you're doing well. Please find attached the meeting notes "
                  "from yesterday's discussion.\n\n"
                  "The team meeting is Thursday at 3 PM in conference room B. "
                  "Bring your laptop and the quarterly report.\n\n"
                  "Best regards,\nSarah\nProject Manager")

    def _set(self, t):
        self.txt.configure(fg=C["text"])
        self.txt.delete("1.0","end")
        self.txt.insert("1.0", t)

    # ── Clear ─────────────────────────────────────────────────────────────────

    def _clear(self):
        self.txt.delete("1.0","end")
        self._ph_restore()
        self.result._show_idle()
        self.dfa.reset()

    # ── Scan bar ──────────────────────────────────────────────────────────────

    def _tick(self, i=0):
        if not self._scanning:
            return
        cols = [C["accent"], C["accent_d"], C["border2"],
                C["border"],  C["border2"],  C["accent_d"]]
        self._scan.configure(bg=cols[i % len(cols)])
        self.after(50, lambda: self._tick(i+1))

    # ── Analyze ───────────────────────────────────────────────────────────────

    def _run(self):
        text = self.txt.get("1.0","end-1c").strip()
        if not text or text == self.PH:
            messagebox.showwarning("Empty", "Paste an email first.", parent=self)
            return

        self._scanning = True
        self.btn.configure(text="Analyzing…", state="disabled",
                           bg=C["muted"])
        self._tick()
        self.after(520, lambda: self._finish(text))

    def _finish(self, text):
        self._scanning = False
        self._scan.configure(bg=C["border"])
        self.btn.configure(text="Analyze", state="normal",
                           bg=C["accent"])

        r = analyze(text)
        self.result.show(r)
        self.dfa.reset()
        self.after(180, lambda: self.dfa.animate(r["state"]))


if __name__ == "__main__":
    App().mainloop()
