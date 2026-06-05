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
BG        = "#F8F9FB"
WHITE     = "#FFFFFF"
BORDER    = "#E4E7EC"
TEXT      = "#101828"
SUB       = "#344054"
MUTED     = "#98A2B3"
BLUE      = "#2563EB"
BLUE_BG   = "#EFF6FF"
BLUE_MID  = "#BFDBFE"
RED       = "#DC2626"
RED_BG    = "#FEF2F2"
GREEN     = "#16A34A"
GREEN_BG  = "#F0FDF4"
AMBER     = "#D97706"
AMBER_BG  = "#FFFBEB"

S_COLORS  = {           # (fill, ring) per DFA state
    "q0": ("#E0E7FF", "#6366F1"),
    "q1": ("#FEF9C3", "#CA8A04"),
    "q2": ("#FFEDD5", "#EA580C"),
    "q3": ("#FEE2E2", "#DC2626"),
}

F_HEAD  = ("Segoe UI", 11, "bold")
F_BODY  = ("Segoe UI", 10)
F_SMALL = ("Segoe UI",  8)
F_MONO  = ("Consolas",  9)
F_SCORE = ("Segoe UI", 34, "bold")


# ── Animated globe ────────────────────────────────────────────────────────────
class Globe(tk.Canvas):
    def __init__(self, parent, size=148, **kw):
        super().__init__(parent, width=size, height=size,
                         bg=WHITE, highlightthickness=0, **kw)
        self.size = size
        self.cx = self.cy = size // 2
        self.r  = size // 2 - 10
        self.angle = 0
        self._draw()

    def _proj(self, lat, lon):
        la = math.radians(lat)
        lo = math.radians(lon + self.angle)
        x = math.cos(la) * math.sin(lo)
        y = math.sin(la)
        z = math.cos(la) * math.cos(lo)
        if z < 0:
            return None
        return self.cx + x * self.r, self.cy - y * self.r

    def _draw(self):
        self.delete("all")
        r = self.r
        self.create_oval(self.cx-r-3, self.cy-r-3, self.cx+r+3, self.cy+r+3,
                         outline=BORDER, width=1)
        self.create_oval(self.cx-r, self.cy-r, self.cx+r, self.cy+r,
                         fill=BLUE_BG, outline=BLUE_MID, width=1)
        for lat in range(-75, 90, 20):
            pts = [p for p in (self._proj(lat, lo) for lo in range(0, 365, 6)) if p]
            for i in range(len(pts)-1):
                self.create_line(*pts[i], *pts[i+1], fill=BLUE_MID, width=1)
        for lon in range(0, 360, 20):
            pts = [p for p in (self._proj(la, lon) for la in range(-90, 92, 6)) if p]
            for i in range(len(pts)-1):
                self.create_line(*pts[i], *pts[i+1], fill=BLUE_MID, width=1)
        for lat, lon in (
            [(la, lo) for la in range(30,70,7) for lo in range(-130,-60,9)] +
            [(la, lo) for la in range(-55,15,7) for lo in range(-80,-35,9)] +
            [(la, lo) for la in range(36,70,6) for lo in range(-10,40,7)]  +
            [(la, lo) for la in range(-35,37,6) for lo in range(-18,52,7)] +
            [(la, lo) for la in range(10,75,6)  for lo in range(40,145,7)] +
            [(la, lo) for la in range(-44,-10,6) for lo in range(114,154,7)]
        ):
            p = self._proj(lat, lon)
            if p:
                self.create_oval(p[0]-2, p[1]-2, p[0]+2, p[1]+2, fill=BLUE, outline="")
        eq = [p for p in (self._proj(0, lo) for lo in range(0, 365, 5)) if p]
        for i in range(len(eq)-1):
            self.create_line(*eq[i], *eq[i+1], fill=BLUE, width=1)

    def animate(self):
        self.angle = (self.angle + 1) % 360
        self._draw()
        self.after(35, self.animate)


# ── Main app ──────────────────────────────────────────────────────────────────
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Spam Detector — Theory of Automata | IQRA University")
        self.configure(bg=BG)
        self.geometry("1100x720")
        self.minsize(900, 600)
        self._setup_styles()
        self._build()
        self.globe.animate()

    def _setup_styles(self):
        s = ttk.Style()
        s.theme_use("clam")
        for name, color in [("Blue", BLUE), ("Red", RED),
                             ("Green", GREEN), ("Amber", AMBER)]:
            s.configure(f"{name}.Horizontal.TProgressbar",
                        troughcolor=BORDER, background=color,
                        bordercolor=WHITE, lightcolor=color, darkcolor=color,
                        thickness=6)

    # ── Layout ────────────────────────────────────────────────────────────────

    def _build(self):
        self._nav()
        body = tk.Frame(self, bg=BG)
        body.pack(fill="both", expand=True, padx=20, pady=16)

        left = tk.Frame(body, bg=BG)
        left.pack(side="left", fill="both", expand=True)

        right = tk.Frame(body, bg=BG, width=220)
        right.pack(side="right", fill="y", padx=(14, 0))
        right.pack_propagate(False)

        self._left_panel(left)
        self._right_panel(right)

    def _nav(self):
        nav = tk.Frame(self, bg=WHITE, height=52)
        nav.pack(fill="x")
        nav.pack_propagate(False)
        # Bottom border line
        tk.Frame(self, bg=BORDER, height=1).pack(fill="x")

        inner = tk.Frame(nav, bg=WHITE)
        inner.pack(fill="both", padx=20)

        tk.Label(inner, text="SpamGuard", font=("Segoe UI", 13, "bold"),
                 bg=WHITE, fg=TEXT).pack(side="left", pady=14)
        tk.Label(inner, text="  ·  Theory of Automata", font=F_BODY,
                 bg=WHITE, fg=MUTED).pack(side="left", pady=14)
        tk.Label(inner, text="IQRA University  ·  DFA / Regex Engine",
                 font=F_SMALL, bg=WHITE, fg=MUTED).pack(side="right", pady=18)

    # ── Left panel ────────────────────────────────────────────────────────────

    def _left_panel(self, p):
        # Input card
        ic = self._card(p)
        ic.pack(fill="both", expand=True, pady=(0, 12))
        tk.Label(ic, text="Email Content", font=F_HEAD, bg=WHITE, fg=TEXT).pack(anchor="w")
        tk.Label(ic, text="Paste an email to scan it for spam signals.",
                 font=F_BODY, bg=WHITE, fg=MUTED).pack(anchor="w", pady=(2, 10))

        self.txt = scrolledtext.ScrolledText(
            ic, height=9, wrap="word", font=F_MONO,
            bg=WHITE, fg=TEXT, insertbackground=BLUE,
            selectbackground=BLUE_MID,
            relief="solid", borderwidth=1, padx=12, pady=10)
        self.txt.pack(fill="both", expand=True)

        self._ph = "Paste the full email body here..."
        self.txt.insert("1.0", self._ph)
        self.txt.configure(fg=MUTED)
        self.txt.bind("<FocusIn>",  self._ph_clear)
        self.txt.bind("<FocusOut>", self._ph_restore)

        br = tk.Frame(ic, bg=WHITE)
        br.pack(fill="x", pady=(10, 0))
        self._btn_primary(br, "Analyze Email", self._analyze).pack(side="left")
        self._btn_ghost(br, "Spam Sample", self._load_spam).pack(side="left", padx=(8, 0))
        self._btn_ghost(br, "Safe Sample",  self._load_safe).pack(side="left", padx=(6, 0))
        self._btn_ghost(br, "Clear", self._clear, danger=True).pack(side="right")

        # Results card
        rc = self._card(p)
        rc.pack(fill="both", expand=True)
        tk.Label(rc, text="Analysis Results", font=F_HEAD, bg=WHITE, fg=TEXT).pack(anchor="w")
        tk.Label(rc, text="DFA state machine output and pattern match breakdown.",
                 font=F_BODY, bg=WHITE, fg=MUTED).pack(anchor="w", pady=(2, 10))

        row = tk.Frame(rc, bg=WHITE)
        row.pack(fill="both", expand=True)

        # Left metrics column
        self._vp = tk.Frame(row, bg=BG, width=190)
        self._vp.pack(side="left", fill="y")
        self._vp.pack_propagate(False)

        sb = tk.Frame(self._vp, bg=WHITE, padx=16, pady=16)
        sb.pack(fill="x")
        tk.Label(sb, text="Spam Score", font=F_SMALL, bg=WHITE, fg=MUTED).pack(anchor="w")
        self.s_lbl = tk.Label(sb, text="—", font=F_SCORE, bg=WHITE, fg=MUTED)
        self.s_lbl.pack(anchor="w")
        self.prog = tk.IntVar(value=0)
        self.pbar = ttk.Progressbar(sb, variable=self.prog, maximum=100,
                                    length=155, style="Blue.Horizontal.TProgressbar")
        self.pbar.pack(anchor="w", pady=(6, 0))

        tk.Frame(self._vp, bg=BORDER, height=1).pack(fill="x")

        self._vblock = tk.Frame(self._vp, bg=BG, padx=16, pady=12)
        self._vblock.pack(fill="x")
        tk.Label(self._vblock, text="Verdict", font=F_SMALL, bg=BG, fg=MUTED).pack(anchor="w")
        self.v_lbl = tk.Label(self._vblock, text="Pending",
                              font=("Segoe UI", 11, "bold"), bg=BG, fg=MUTED)
        self.v_lbl.pack(anchor="w", pady=(3, 0))

        tk.Frame(self._vp, bg=BORDER, height=1).pack(fill="x")

        db = tk.Frame(self._vp, bg=WHITE, padx=16, pady=12)
        db.pack(fill="x")
        tk.Label(db, text="DFA Final State", font=F_SMALL, bg=WHITE, fg=MUTED).pack(anchor="w")
        self.st_lbl = tk.Label(db, text="—",
                               font=("Consolas", 14, "bold"), bg=WHITE, fg=TEXT)
        self.st_lbl.pack(anchor="w", pady=(3, 0))

        # Vertical divider
        tk.Frame(row, bg=BORDER, width=1).pack(side="left", fill="y", padx=(10, 0))

        # Detail log
        self.detail = scrolledtext.ScrolledText(
            row, font=F_MONO, bg=WHITE, fg=SUB,
            state="disabled", relief="flat", borderwidth=0,
            padx=14, pady=12, selectbackground=BLUE_BG)
        self.detail.pack(side="left", fill="both", expand=True)

    # ── Right panel ───────────────────────────────────────────────────────────

    def _right_panel(self, p):
        gc = self._card(p)
        gc.pack(fill="x")
        tk.Label(gc, text="Automata Engine", font=("Segoe UI", 9, "bold"),
                 bg=WHITE, fg=TEXT).pack(anchor="w")
        tk.Label(gc, text="Live rotating globe", font=F_SMALL, bg=WHITE, fg=MUTED).pack(anchor="w", pady=(1, 8))
        self.globe = Globe(gc, size=148)
        self.globe.pack()

        dc = self._card(p)
        dc.pack(fill="x", pady=(10, 0))
        tk.Label(dc, text="DFA State Diagram", font=("Segoe UI", 9, "bold"),
                 bg=WHITE, fg=TEXT).pack(anchor="w")
        tk.Label(dc, text="Transitions on keyword count", font=F_SMALL,
                 bg=WHITE, fg=MUTED).pack(anchor="w", pady=(1, 8))
        self.dfa_c = tk.Canvas(dc, width=180, height=140, bg=WHITE, highlightthickness=0)
        self.dfa_c.pack()
        self._draw_dfa()

        fc = self._card(p)
        fc.pack(fill="x", pady=(10, 0))
        tk.Label(fc, text="Team", font=F_SMALL, bg=WHITE, fg=MUTED).pack(anchor="w")
        for name in ("Moniza Fatima", "Laraib Suikarno", "Miss Alisha Farmaan"):
            tk.Label(fc, text=name, font=("Segoe UI", 9), bg=WHITE, fg=SUB).pack(anchor="w")

    # ── DFA diagram ───────────────────────────────────────────────────────────

    def _draw_dfa(self, hl=None):
        c = self.dfa_c
        c.delete("all")
        nodes = [("q0", 22, 72), ("q1", 72, 28), ("q2", 132, 28), ("q3", 160, 80)]
        pos = {}
        for sid, x, y in nodes:
            fill_c, ring_c = S_COLORS[sid]
            r = 18
            if sid == "q3":
                c.create_oval(x-r-4, y-r-4, x+r+4, y+r+4,
                              outline=ring_c, width=1, dash=(3, 3))
            active = (sid == hl)
            c.create_oval(x-r, y-r, x+r, y+r,
                          fill=ring_c if active else fill_c,
                          outline=ring_c, width=2 if active else 1)
            c.create_text(x, y, text=sid, font=("Consolas", 8, "bold"),
                          fill=WHITE if active else ring_c)
            pos[sid] = (x, y, r)

        for a, b in [("q0", "q1"), ("q1", "q2"), ("q2", "q3")]:
            x1,y1,r1 = pos[a]; x2,y2,r2 = pos[b]
            dx, dy = x2-x1, y2-y1
            d  = math.hypot(dx, dy)
            sx, sy = x1 + dx/d*r1, y1 + dy/d*r1
            ex, ey = x2 - dx/d*r2, y2 - dy/d*r2
            c.create_line(sx, sy, ex, ey, arrow=tk.LAST,
                          fill=MUTED, width=1, arrowshape=(6, 8, 3))

        x, y, _ = pos["q3"]
        c.create_arc(x-18, y-34, x+18, y-2, start=0, extent=260,
                     style="arc", outline=RED, width=1)
        c.create_text(90, 128, text="q0  →  q1  →  q2  →  q3",
                      font=("Segoe UI", 7), fill=MUTED)

    # ── Widgets ───────────────────────────────────────────────────────────────

    def _card(self, parent):
        return tk.Frame(parent, bg=WHITE, padx=16, pady=14,
                        highlightbackground=BORDER, highlightthickness=1)

    def _btn_primary(self, parent, text, cmd):
        return tk.Button(parent, text=text, command=cmd,
                         font=("Segoe UI", 10, "bold"),
                         bg=BLUE, fg=WHITE, activebackground="#1D4ED8",
                         activeforeground=WHITE, relief="flat",
                         cursor="hand2", padx=18, pady=7, bd=0)

    def _btn_ghost(self, parent, text, cmd, danger=False):
        fg = RED if danger else SUB
        return tk.Button(parent, text=text, command=cmd, font=F_BODY,
                         bg=WHITE, fg=fg, activebackground=BG,
                         activeforeground=fg, relief="flat",
                         cursor="hand2", padx=12, pady=7, bd=0,
                         highlightbackground=BORDER, highlightthickness=1)

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
        self.s_lbl.configure(text="—", fg=MUTED)
        self.v_lbl.configure(text="Pending", fg=MUTED)
        self._vblock.configure(bg=BG)
        self.v_lbl.configure(bg=BG)
        for w in self._vblock.winfo_children():
            w.configure(bg=BG)
        self.st_lbl.configure(text="—", fg=TEXT)
        self.prog.set(0)
        self.pbar.configure(style="Blue.Horizontal.TProgressbar")
        self._set_detail("")
        self._draw_dfa()

    # ── Analyze ───────────────────────────────────────────────────────────────

    def _analyze(self):
        text = self.txt.get("1.0", "end-1c").strip()
        if not text or text == self._ph:
            messagebox.showwarning("No Input", "Paste an email before analyzing.", parent=self)
            return

        r = analyze_email(text)
        col, bg_c, style = {
            "SPAM":       (RED,   RED_BG,   "Red"),
            "SUSPICIOUS": (AMBER, AMBER_BG, "Amber"),
            "SAFE":       (GREEN, GREEN_BG, "Green"),
        }[r["verdict"]]

        self.s_lbl.configure(text=f"{r['score']}%", fg=col)
        self.prog.set(r["score"])
        self.pbar.configure(style=f"{style}.Horizontal.TProgressbar")

        # Verdict block recolor
        self._vblock.configure(bg=bg_c)
        for w in self._vblock.winfo_children():
            w.configure(bg=bg_c)
        self.v_lbl.configure(text=r["verdict"], fg=col, bg=bg_c)

        self.st_lbl.configure(text=r["state"], fg=col)
        self._draw_dfa(hl=r["state"])

        lines = [
            f"  Verdict       {r['verdict']}",
            f"  Spam Score    {r['score']}%",
            f"  DFA State     {r['state']}",
            f"  Accepted      {'Yes' if r['accepted'] else 'No'}",
            f"  Keyword Hits  {r['total_kw']}",
            "",
            "  ── Keyword Matches " + "─" * 32,
        ]
        if r["kw_hits"]:
            for cat, kws in r["kw_hits"].items():
                lines.append(f"\n  {cat}")
                lines += [f"    ·  {k}" for k in kws]
        else:
            lines.append("  None detected.")

        lines += ["", "  ── Regex Matches " + "─" * 34]
        lines += ([f"  ·  {lbl}  ×{n}" for lbl, n in r["re_hits"]]
                  if r["re_hits"] else ["  None detected."])

        lines += ["", "  ── DFA Path " + "─" * 38,
                  "  q0  →  q1  →  q2  →  q3",
                  f"  Halted at  {r['state']}"]

        self._set_detail("\n".join(lines))

    def _set_detail(self, txt):
        self.detail.configure(state="normal")
        self.detail.delete("1.0", "end")
        if txt:
            self.detail.insert("1.0", txt)
        self.detail.configure(state="disabled")


if __name__ == "__main__":
    App().mainloop()
