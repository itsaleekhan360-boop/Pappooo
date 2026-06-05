import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import re
import math

# ── Spam keyword database ─────────────────────────────────────────────────────
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


# ── DFA ───────────────────────────────────────────────────────────────────────
class SpamDFA:
    """
    States: q0 (clean) → q1 (low) → q2 (medium) → q3 (spam/accept)
    Transitions driven by aggregated keyword hit count.
    """
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
    text_lower = text.lower()
    dfa = SpamDFA()

    kw_hits, total_kw = {}, 0
    for cat, keywords in SPAM_KEYWORDS.items():
        found = [k for k in keywords if k in text_lower]
        if found:
            kw_hits[cat] = found
            total_kw += len(found)

    re_hits = [(lbl, len(re.findall(pat, text)))
               for pat, lbl in REGEX_PATTERNS
               if re.search(pat, text)]

    state = dfa.run(total_kw)
    accepted = (state == "q3")

    score = min(int(((total_kw + len(re_hits) * 0.5) / 20) * 100), 100)
    if accepted and score < 70:
        score = 70

    verdict = "SPAM" if (score >= 60 or accepted) else "SUSPICIOUS" if score >= 30 else "SAFE"

    return {
        "verdict": verdict, "score": score,
        "state": state, "accepted": accepted,
        "kw_hits": kw_hits, "total_kw": total_kw,
        "re_hits": re_hits,
    }


# ── Theme ─────────────────────────────────────────────────────────────────────
BG      = "#0F1117"
SURFACE = "#161B27"
CARD    = "#1C2333"
BORDER  = "#2A3A5C"
BLUE    = "#4A90D9"
BLUE_LT = "#6AAFF0"
TEXT    = "#E8EDF5"
MUTED   = "#6B7FA3"
RED     = "#E05252"
GREEN   = "#52C97A"
AMBER   = "#F0A030"
GOLD    = "#E8C56A"

F_UI    = ("Segoe UI", 10)
F_MONO  = ("Consolas", 9)
F_HEAD  = ("Segoe UI", 12, "bold")
F_BIG   = ("Segoe UI", 30, "bold")


# ── Globe ─────────────────────────────────────────────────────────────────────
class Globe(tk.Canvas):
    def __init__(self, parent, size=160, **kw):
        super().__init__(parent, width=size, height=size,
                         bg=BG, highlightthickness=0, **kw)
        self.size = size
        self.cx = self.cy = size // 2
        self.r = size // 2 - 12
        self.angle = 0
        self._draw()

    def _proj(self, lat, lon):
        la, lo = math.radians(lat), math.radians(lon + self.angle)
        x = math.cos(la) * math.sin(lo)
        y = math.sin(la)
        z = math.cos(la) * math.cos(lo)
        if z < 0:
            return None
        return self.cx + x * self.r, self.cy - y * self.r

    def _draw(self):
        self.delete("all")
        r = self.r
        # Glow ring
        self.create_oval(self.cx-r-4, self.cy-r-4, self.cx+r+4, self.cy+r+4,
                         outline=BORDER, width=1)
        # Sphere fill
        self.create_oval(self.cx-r, self.cy-r, self.cx+r, self.cy+r,
                         fill="#080D18", outline=BLUE, width=1)
        # Grid lines
        for lat in range(-75, 90, 20):
            pts = [p for p in (self._proj(lat, lo) for lo in range(0, 365, 6)) if p]
            for i in range(len(pts)-1):
                self.create_line(*pts[i], *pts[i+1], fill=BORDER, width=1)
        for lon in range(0, 360, 20):
            pts = [p for p in (self._proj(la, lon) for la in range(-90, 92, 6)) if p]
            for i in range(len(pts)-1):
                self.create_line(*pts[i], *pts[i+1], fill=BORDER, width=1)
        # Continents
        for lat, lon in (
            [(la, lo) for la in range(30,70,7) for lo in range(-130,-60,9)] +
            [(la, lo) for la in range(-55,15,7) for lo in range(-80,-35,9)] +
            [(la, lo) for la in range(36,70,6) for lo in range(-10,40,7)] +
            [(la, lo) for la in range(-35,37,6) for lo in range(-18,52,7)] +
            [(la, lo) for la in range(10,75,6) for lo in range(40,145,7)] +
            [(la, lo) for la in range(-44,-10,6) for lo in range(114,154,7)]
        ):
            p = self._proj(lat, lon)
            if p:
                self.create_oval(p[0]-2, p[1]-2, p[0]+2, p[1]+2, fill=BLUE_LT, outline="")
        # Equator
        eq = [p for p in (self._proj(0, lo) for lo in range(0, 365, 5)) if p]
        for i in range(len(eq)-1):
            self.create_line(*eq[i], *eq[i+1], fill=BLUE, width=1)

    def animate(self):
        self.angle = (self.angle + 1) % 360
        self._draw()
        self.after(30, self.animate)


# ── Main App ──────────────────────────────────────────────────────────────────
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Spam Email Detector — Theory of Automata | IQRA University")
        self.configure(bg=BG)
        self.geometry("1050x700")
        self.minsize(860, 580)
        self._build()
        self.globe.animate()

    def _build(self):
        # Header
        hdr = tk.Frame(self, bg="#0D1420", height=48)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)
        tk.Label(hdr, text="SPAM EMAIL DETECTOR", font=("Segoe UI", 13, "bold"),
                 bg="#0D1420", fg=TEXT).pack(side="left", padx=20, pady=12)
        tk.Label(hdr, text="Theory of Automata  ·  DFA / Regex  ·  IQRA University",
                 font=("Segoe UI", 9), bg="#0D1420", fg=MUTED).pack(side="right", padx=20)

        sep = tk.Frame(self, bg=BORDER, height=1)
        sep.pack(fill="x")

        # Body
        body = tk.Frame(self, bg=BG)
        body.pack(fill="both", expand=True, padx=12, pady=10)

        left = tk.Frame(body, bg=BG)
        left.pack(side="left", fill="both", expand=True)

        right = tk.Frame(body, bg=BG, width=200)
        right.pack(side="right", fill="y", padx=(10, 0))
        right.pack_propagate(False)

        self._build_left(left)
        self._build_right(right)

    def _build_left(self, p):
        # Input section
        tk.Label(p, text="Email Content", font=F_HEAD, bg=BG, fg=TEXT).pack(anchor="w")
        tk.Label(p, text="Paste the email body below to analyze for spam indicators.",
                 font=("Segoe UI", 9), bg=BG, fg=MUTED).pack(anchor="w", pady=(0, 6))

        self.txt = scrolledtext.ScrolledText(
            p, height=9, wrap="word", font=F_MONO,
            bg=CARD, fg=TEXT, insertbackground=BLUE_LT,
            selectbackground=BORDER, relief="flat", borderwidth=0,
            padx=10, pady=10)
        self.txt.pack(fill="both", expand=True)
        self._ph = "Paste email content here..."
        self.txt.insert("1.0", self._ph)
        self.txt.configure(fg=MUTED)
        self.txt.bind("<FocusIn>",  self._ph_clear)
        self.txt.bind("<FocusOut>", self._ph_restore)

        # Buttons
        br = tk.Frame(p, bg=BG)
        br.pack(fill="x", pady=8)
        self._btn(br, "Analyze", self._analyze, BLUE, side="left")
        self._btn(br, "Load Spam Sample", self._load_spam, "#2A3A4A", side="left", px=6)
        self._btn(br, "Load Safe Sample", "#1A3A25", self._load_safe, side="left", px=0)
        self._btn(br, "Clear", "#3A1A1A", self._clear, side="right")

        tk.Frame(p, bg=BORDER, height=1).pack(fill="x")

        # Results section
        res = tk.Frame(p, bg=BG)
        res.pack(fill="both", expand=True, pady=(8, 0))

        # Verdict panel
        vp = tk.Frame(res, bg=SURFACE, width=200)
        vp.pack(side="left", fill="y")
        vp.pack_propagate(False)

        tk.Label(vp, text="VERDICT", font=("Segoe UI", 8, "bold"),
                 bg=SURFACE, fg=MUTED).pack(pady=(16, 4))
        self.v_lbl = tk.Label(vp, text="—", font=F_BIG, bg=SURFACE, fg=MUTED)
        self.v_lbl.pack()

        tk.Label(vp, text="SPAM SCORE", font=("Segoe UI", 8, "bold"),
                 bg=SURFACE, fg=MUTED).pack(pady=(14, 2))
        self.s_lbl = tk.Label(vp, text="—", font=("Segoe UI", 22, "bold"),
                              bg=SURFACE, fg=MUTED)
        self.s_lbl.pack()

        self.prog = tk.IntVar(value=0)
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("S.Horizontal.TProgressbar",
                        troughcolor=CARD, background=BLUE,
                        bordercolor=SURFACE, lightcolor=BLUE, darkcolor=BLUE)
        ttk.Progressbar(vp, variable=self.prog, maximum=100, length=150,
                        style="S.Horizontal.TProgressbar").pack(padx=16, pady=(4, 0))

        tk.Label(vp, text="DFA State", font=("Segoe UI", 8, "bold"),
                 bg=SURFACE, fg=MUTED).pack(pady=(14, 2))
        self.st_lbl = tk.Label(vp, text="—", font=("Consolas", 13, "bold"),
                               bg=SURFACE, fg=GOLD)
        self.st_lbl.pack(pady=(0, 16))

        # Detail box
        self.detail = scrolledtext.ScrolledText(
            res, font=F_MONO, bg=CARD, fg=TEXT,
            state="disabled", relief="flat", borderwidth=0,
            padx=10, pady=10, selectbackground=BORDER)
        self.detail.pack(side="left", fill="both", expand=True, padx=(8, 0))

    def _build_right(self, p):
        tk.Label(p, text="Live Analysis", font=("Segoe UI", 9, "bold"),
                 bg=BG, fg=MUTED).pack(pady=(4, 6))
        self.globe = Globe(p, size=160)
        self.globe.pack()

        tk.Frame(p, bg=BORDER, height=1).pack(fill="x", pady=10)
        tk.Label(p, text="DFA States", font=("Segoe UI", 8, "bold"),
                 bg=BG, fg=MUTED).pack(pady=(0, 4))

        self.dfa_c = tk.Canvas(p, width=185, height=155, bg=BG, highlightthickness=0)
        self.dfa_c.pack()
        self._draw_dfa()

        tk.Frame(p, bg=BORDER, height=1).pack(fill="x", pady=10)
        tk.Label(p, text="Moniza Fatima · Laraib Suikarno",
                 font=("Segoe UI", 7), bg=BG, fg=MUTED).pack()
        tk.Label(p, text="Miss Alisha Farmaan",
                 font=("Segoe UI", 7), bg=BG, fg=MUTED).pack(pady=(2, 0))

    def _draw_dfa(self, hl=None):
        c = self.dfa_c
        c.delete("all")
        nodes = [("q0", 22, 78), ("q1", 72, 28), ("q2", 138, 28), ("q3", 168, 88)]
        colors = {"q0": BLUE, "q1": BLUE_LT, "q2": AMBER, "q3": RED}
        pos = {}
        for sid, x, y in nodes:
            col = colors[sid]
            if sid == "q3":
                c.create_oval(x-20, y-20, x+20, y+20, outline=col, width=1)
            bw = 2 if sid == hl else 1
            bc = TEXT if sid == hl else col
            c.create_oval(x-14, y-14, x+14, y+14, fill=CARD, outline=bc, width=bw)
            c.create_text(x, y, text=sid, font=("Consolas", 8, "bold"), fill=TEXT)
            pos[sid] = (x, y)
        for a, b in [("q0","q1"),("q1","q2"),("q2","q3")]:
            x1,y1 = pos[a]; x2,y2 = pos[b]
            c.create_line(x1+14, y1, x2-14, y2, arrow=tk.LAST,
                          fill=MUTED, width=1, arrowshape=(5,7,3))
        x,y = pos["q3"]
        c.create_arc(x-20, y-36, x+20, y-4, start=0, extent=260,
                     style="arc", outline=RED, width=1)
        c.create_text(92, 148, text="q0 → q1 → q2 → q3",
                      font=("Segoe UI", 6), fill=MUTED)

    def _btn(self, parent, text, cmd, color, side="left", px=6):
        # handle positional arg order mismatch
        if callable(color):
            color, cmd = cmd, color
        b = tk.Button(parent, text=text, command=cmd, font=("Segoe UI", 9),
                      bg=color, fg=TEXT, activebackground=BLUE,
                      activeforeground=TEXT, relief="flat", cursor="hand2",
                      padx=12, pady=5, bd=0)
        b.pack(side=side, padx=(0, px))
        return b

    def _ph_clear(self, _=None):
        if self.txt.get("1.0", "end-1c") == self._ph:
            self.txt.delete("1.0", "end")
            self.txt.configure(fg=TEXT)

    def _ph_restore(self, _=None):
        if not self.txt.get("1.0", "end-1c").strip():
            self.txt.insert("1.0", self._ph)
            self.txt.configure(fg=MUTED)

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

    def _clear(self):
        self.txt.delete("1.0", "end")
        self._ph_restore()
        self.v_lbl.configure(text="—", fg=MUTED)
        self.s_lbl.configure(text="—", fg=MUTED)
        self.st_lbl.configure(text="—")
        self.prog.set(0)
        self._set_detail("")
        self._draw_dfa()

    def _analyze(self):
        text = self.txt.get("1.0", "end-1c").strip()
        if not text or text == self._ph:
            messagebox.showwarning("No Input", "Paste email text before analyzing.", parent=self)
            return

        r = analyze_email(text)
        col = {" SPAM": RED, "SUSPICIOUS": AMBER, "SAFE": GREEN}.get(r["verdict"], TEXT)
        col = RED if r["verdict"] == "SPAM" else AMBER if r["verdict"] == "SUSPICIOUS" else GREEN

        self.v_lbl.configure(text=r["verdict"], fg=col)
        self.s_lbl.configure(text=f"{r['score']}%", fg=col)
        self.prog.set(r["score"])
        ttk.Style().configure("S.Horizontal.TProgressbar", background=col)
        self.st_lbl.configure(text=r["state"])
        self._draw_dfa(hl=r["state"])

        lines = [
            "=" * 52,
            "  ANALYSIS REPORT",
            "=" * 52,
            f"  Verdict      : {r['verdict']}",
            f"  Spam Score   : {r['score']}%",
            f"  DFA State    : {r['state']}",
            f"  DFA Accepted : {'Yes (SPAM)' if r['accepted'] else 'No'}",
            f"  Keyword Hits : {r['total_kw']}",
            "",
            "─" * 52,
            "  KEYWORD MATCHES",
            "─" * 52,
        ]
        if r["kw_hits"]:
            for cat, kws in r["kw_hits"].items():
                lines.append(f"  [{cat}]")
                lines += [f"    · {k}" for k in kws]
        else:
            lines.append("  None detected.")

        lines += ["", "─" * 52, "  REGEX MATCHES", "─" * 52]
        if r["re_hits"]:
            lines += [f"  · {lbl}  (×{n})" for lbl, n in r["re_hits"]]
        else:
            lines.append("  None detected.")

        lines += ["", "─" * 52, "  DFA TRANSITIONS",
                  "─" * 52,
                  "  q0 → q1 → q2 → q3",
                  f"  Reached: {r['state']}",
                  "=" * 52]

        self._set_detail("\n".join(lines))

    def _set_detail(self, txt):
        self.detail.configure(state="normal")
        self.detail.delete("1.0", "end")
        if txt:
            self.detail.insert("1.0", txt)
        self.detail.configure(state="disabled")


if __name__ == "__main__":
    App().mainloop()
