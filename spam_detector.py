"""SpamGuard — Theory of Automata | IQRA University"""
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
    (r"(?i)\bgift\b",                       "Keyword: gift"),
    (r"(?i)\boffer\b",                      "Keyword: offer"),
    (r"(?i)dear\s+(sir|madam|friend|user)", "Generic salutation"),
    (r"(?i)\bunsubscribe\b",                "Unsubscribe link"),
]

class SpamDFA:
    T = {("q0",0):"q0",("q0",1):"q1",("q1",1):"q1",("q1",2):"q2",
         ("q2",1):"q2",("q2",2):"q3",("q3",1):"q3",("q3",2):"q3"}
    def run(self, n):
        s, r = "q0", n
        while r > 0:
            step = min(r, 2); s = self.T.get((s,step), s); r -= step
        return s

def run_analysis(text):
    tl = text.lower(); dfa = SpamDFA(); kw = {}; nkw = 0
    for cat, words in SPAM_KEYWORDS.items():
        found = [w for w in words if w in tl]
        if found: kw[cat] = found; nkw += len(found)
    rx = [(lbl,n) for lbl,n in
          ((lbl,len(re.findall(p,text))) for p,lbl in REGEX_PATTERNS) if n]
    state = dfa.run(nkw); accepted = state == "q3"
    score = min(int(((nkw + len(rx)*.5)/20)*100), 100)
    if accepted and score < 70: score = 70
    verdict = ("SPAM" if score>=60 or accepted else
               "SUSPICIOUS" if score>=30 else "SAFE")
    return dict(verdict=verdict, score=score, state=state,
                accepted=accepted, kw=kw, nkw=nkw, rx=rx)


# ══════════════════════════════════════════════════════════════════════════════
#  DESIGN SYSTEM  — Framer/Launchfolio-inspired
# ══════════════════════════════════════════════════════════════════════════════

# Palette — warm near-black (not cold grey, not pure black)
BG     = "#0C0C0E"   # page canvas
CARD   = "#131316"   # card surface
CARD_H = "#1A1A1E"   # hovered / slightly elevated card
BORDER = "#242428"   # card stroke
BORDER2= "#2E2E34"   # stronger stroke
BLUE   = "#5865F2"   # primary CTA  (Linear indigo)
BLUE_D = "#4752C4"
TEXT   = "#EFEFEF"   # primary text
DIM    = "#888896"   # secondary text
MUTED  = "#3E3E48"   # placeholder / muted

# Verdict colours — fg, card-bg, accent-border
V = {
    "SPAM":       ("#F04747", "#160A0A", "#3A1212"),
    "SUSPICIOUS": ("#F5A623", "#160F04", "#3A2808"),
    "SAFE":       ("#23D160", "#05140C", "#0E3320"),
}

# DFA node accent colours
DFA_C = {"q0":"#818CF8","q1":"#38BDF8","q2":"#FBBF24","q3":"#F04747"}

# Typography — weight contrast drives hierarchy, not font-size jumps
F = {
    "nav":    ("Segoe UI", 11, "bold"),
    "label":  ("Segoe UI",  8, "bold"),   # ALLCAPS labels
    "body":   ("Segoe UI", 10),
    "body_b": ("Segoe UI", 10, "bold"),
    "sm":     ("Segoe UI",  9),
    "xs":     ("Segoe UI",  8),
    "mono":   ("Consolas",  9),
    "num_lg": ("Segoe UI", 36, "bold"),   # score number
    "num_md": ("Segoe UI", 20, "bold"),   # state / count
    "verdict":("Segoe UI", 28, "bold"),
}

GAP = 8   # bento gap between cards
P   = 18  # card inner padding


def card(parent, bg=None, border=None):
    """Returns (outer, inner) frames. Pack/grid the outer; put children in inner."""
    bg     = bg     or CARD
    border = border or BORDER
    outer  = tk.Frame(parent, bg=border, padx=1, pady=1)
    inner  = tk.Frame(outer, bg=bg)
    inner.pack(fill="both", expand=True)
    return outer, inner


# ══════════════════════════════════════════════════════════════════════════════
#  DFA FOOTER STRIP
# ══════════════════════════════════════════════════════════════════════════════

class DFAStrip(tk.Canvas):
    NODES = ["q0","q1","q2","q3"]; NR = 13; GAP_N = 90; H = 50

    def __init__(self, parent, **kw):
        W = len(self.NODES)*self.NR*2 + (len(self.NODES)-1)*self.GAP_N + 80
        super().__init__(parent, width=W, height=self.H,
                         bg=CARD, highlightthickness=0, **kw)
        self._lit: set = set()
        self._draw()

    def _cx(self, i):
        span  = (len(self.NODES)-1)*self.GAP_N
        start = (int(self["width"]) - span) // 2
        return start + i*self.GAP_N

    def _draw(self):
        self.delete("all"); cy = self.H//2
        xs = [self._cx(i) for i in range(4)]
        for i in range(3):
            a, b = self.NODES[i], self.NODES[i+1]
            col = DFA_C[a] if (a in self._lit and b in self._lit) else BORDER2
            self.create_line(xs[i]+self.NR, cy, xs[i+1]-self.NR, cy, fill=col, width=1)
        x3 = xs[3]; lit3 = "q3" in self._lit
        self.create_arc(x3-15, cy-24, x3+15, cy-2, start=20, extent=200,
                        style="arc", outline=DFA_C["q3"] if lit3 else MUTED, width=1)
        for i, s in enumerate(self.NODES):
            x = xs[i]; lit = s in self._lit; nc = DFA_C[s]
            if s == "q3":
                self.create_oval(x-self.NR-4, cy-self.NR-4,
                                 x+self.NR+4, cy+self.NR+4,
                                 outline=nc if lit else MUTED, width=1, dash=(3,3))
            self.create_oval(x-self.NR, cy-self.NR, x+self.NR, cy+self.NR,
                             fill=CARD_H if lit else CARD,
                             outline=nc if lit else MUTED, width=2 if lit else 1)
            self.create_text(x, cy, text=s, font=("Consolas",8,"bold"),
                             fill=nc if lit else DIM)
        cur = (max(self._lit, key=lambda s: self.NODES.index(s)) if self._lit else None)
        W = int(self["width"])
        self.create_text(W-12, cy, text=f"state  {cur or '—'}",
                         font=("Consolas",8), fill=DIM, anchor="e")

    def animate(self, final, step=0):
        idx = self.NODES.index(final)
        if step <= idx:
            self._lit = set(self.NODES[:step+1]); self._draw()
            self.after(240, lambda: self.animate(final, step+1))

    def reset(self): self._lit = set(); self._draw()


# ══════════════════════════════════════════════════════════════════════════════
#  METRIC CARD  — small stat tile (score, state, etc.)
# ══════════════════════════════════════════════════════════════════════════════

class MetricCard(tk.Frame):
    def __init__(self, parent, label, **kw):
        outer, self._inner = card(parent)
        outer.__class__ = MetricCard           # expose pack/grid on outer
        # We pack content into self._inner
        self._bg = CARD
        ip = tk.Frame(self._inner, bg=CARD, padx=P, pady=P)
        ip.pack(fill="both", expand=True)
        tk.Label(ip, text=label, font=F["label"], bg=CARD, fg=MUTED).pack(anchor="w")
        self._val = tk.Label(ip, text="—", font=F["num_lg"], bg=CARD, fg=MUTED)
        self._val.pack(anchor="w", pady=(4,0))
        self._sub = tk.Label(ip, text="", font=F["xs"], bg=CARD, fg=MUTED)
        self._sub.pack(anchor="w")
        # Forward geometry methods to outer
        self._outer = outer
        self.pack  = outer.pack
        self.grid  = outer.grid
        self.place = outer.place

    def set(self, value, color=TEXT, sub=""):
        self._val.configure(text=value, fg=color)
        self._sub.configure(text=sub)

    def animate_num(self, target, color, sub="", step=0, frames=36):
        t = 1-(1-step/frames)**3
        self._val.configure(text=f"{int(target*t)}%", fg=color)
        self._sub.configure(text=sub)
        if step < frames:
            self.after(14, lambda: self.animate_num(target,color,sub,step+1,frames))


# ══════════════════════════════════════════════════════════════════════════════
#  APP
# ══════════════════════════════════════════════════════════════════════════════

class App(tk.Tk):
    PH = "Paste the full email body here…"

    def __init__(self):
        super().__init__()
        self.title("SpamGuard — Theory of Automata  |  IQRA University")
        self.configure(bg=BG)
        self.geometry("1180x720")
        self.minsize(980, 600)
        self._scanning = False
        self._build()

    # ── Layout ────────────────────────────────────────────────────────────────

    def _build(self):
        self._nav()
        self._body()
        self._footer()

    def _nav(self):
        n = tk.Frame(self, bg=CARD, height=46)
        n.pack(fill="x"); n.pack_propagate(False)
        tk.Frame(self, bg=BORDER, height=1).pack(fill="x")
        f = tk.Frame(n, bg=CARD)
        f.pack(fill="both", expand=True, padx=24)
        # Logo row
        logo = tk.Frame(f, bg=CARD)
        logo.pack(side="left", pady=11)
        # Breathing accent dot
        self._dot = tk.Canvas(logo, width=8, height=8,
                              bg=CARD, highlightthickness=0)
        self._dot.pack(side="left", padx=(0,9))
        self._dot.create_oval(0,0,8,8, fill=BLUE, outline="")
        self._dot_on = True
        self._breathe()
        tk.Label(logo, text="SpamGuard", font=F["nav"],
                 bg=CARD, fg=TEXT).pack(side="left")
        tk.Label(logo, text="  /  Theory of Automata",
                 font=F["body"], bg=CARD, fg=DIM).pack(side="left")
        tk.Label(f, text="IQRA University  ·  DFA + Regex",
                 font=F["xs"], bg=CARD, fg=MUTED).pack(side="right", pady=16)

    def _breathe(self):
        self._dot_on = not self._dot_on
        self._dot.delete("all")
        self._dot.create_oval(0,0,8,8,
                              fill=BLUE if self._dot_on else BLUE_D, outline="")
        self.after(900, self._breathe)

    def _body(self):
        body = tk.Frame(self, bg=BG)
        body.pack(fill="both", expand=True)

        # ── Left: email input (fixed 460px) ──────────────────────────────
        left_wrap = tk.Frame(body, bg=BG, width=460)
        left_wrap.pack(side="left", fill="y", padx=(GAP,0), pady=GAP)
        left_wrap.pack_propagate(False)
        self._build_input(left_wrap)

        # ── Right: bento grid ─────────────────────────────────────────────
        right = tk.Frame(body, bg=BG)
        right.pack(side="left", fill="both", expand=True,
                   padx=GAP, pady=GAP)

        self._build_bento(right)

    def _build_input(self, parent):
        # "EMAIL BODY" label
        lf = tk.Frame(parent, bg=BG)
        lf.pack(fill="x", pady=(0, GAP))
        tk.Label(lf, text="EMAIL BODY", font=F["label"],
                 bg=BG, fg=MUTED).pack(side="left")

        # Textarea card
        self._tf_border = tk.Frame(parent, bg=BORDER, padx=1, pady=1)
        self._tf_border.pack(fill="both", expand=True)
        self.txt = tk.Text(
            self._tf_border, wrap="word", font=F["mono"],
            bg=CARD, fg=TEXT, insertbackground=BLUE,
            selectbackground=BORDER2, selectforeground=TEXT,
            relief="flat", bd=0, padx=16, pady=14,
            spacing1=3, spacing3=3, undo=True)
        self.txt.pack(fill="both", expand=True)
        self.txt.insert("1.0", self.PH)
        self.txt.configure(fg=MUTED)
        self.txt.bind("<FocusIn>",  lambda e: [self._ph_clear(),
                      self._tf_border.configure(bg=BLUE)])
        self.txt.bind("<FocusOut>", lambda e: [self._ph_restore(),
                      self._tf_border.configure(bg=BORDER)])

        # Scan pulse bar
        self._scanbar = tk.Frame(parent, bg=BORDER, height=2)
        self._scanbar.pack(fill="x")

        # Buttons
        bf = tk.Frame(parent, bg=BG)
        bf.pack(fill="x", pady=(GAP, 0))

        self.btn = tk.Button(
            bf, text="Analyze", command=self._run,
            font=F["body_b"], bg=BLUE, fg="white",
            activebackground=BLUE_D, activeforeground="white",
            relief="flat", cursor="hand2", padx=20, pady=9, bd=0)
        self.btn.pack(side="left")

        for txt, cmd in [("Spam sample", self._sample_spam),
                         ("Safe sample",  self._sample_safe)]:
            tk.Button(bf, text=txt, command=cmd,
                      font=F["body"], bg=CARD_H, fg=DIM,
                      activebackground=BORDER2, activeforeground=TEXT,
                      relief="flat", cursor="hand2",
                      padx=14, pady=9, bd=0,
                      highlightbackground=BORDER,
                      highlightthickness=1).pack(side="left", padx=(GAP,0))

        tk.Button(bf, text="Clear", command=self._clear,
                  font=F["body"], bg=BG, fg=MUTED,
                  activebackground=BG, activeforeground=DIM,
                  relief="flat", cursor="hand2",
                  padx=12, pady=9, bd=0).pack(side="right")

    def _build_bento(self, parent):
        """Build the right-side bento grid — stable across idle/result states."""
        parent.columnconfigure(0, weight=1, uniform="col")
        parent.columnconfigure(1, weight=1, uniform="col")
        parent.columnconfigure(2, weight=1, uniform="col")
        parent.columnconfigure(3, weight=1, uniform="col")
        parent.rowconfigure(0, weight=0)   # top metric row
        parent.rowconfigure(1, weight=0)   # verdict row
        parent.rowconfigure(2, weight=1)   # findings row

        # ── Row 0: four metric tiles ──────────────────────────────────────
        def metric_tile(col, label):
            o, i = card(parent)
            o.grid(row=0, column=col, sticky="nsew",
                   padx=(0 if col==0 else GAP//2, 0 if col==3 else GAP//2),
                   pady=(0, GAP))
            ip = tk.Frame(i, bg=CARD, padx=P, pady=16)
            ip.pack(fill="both", expand=True)
            tk.Label(ip, text=label, font=F["label"],
                     bg=CARD, fg=MUTED).pack(anchor="w")
            val = tk.Label(ip, text="—", font=F["num_md"], bg=CARD, fg=MUTED)
            val.pack(anchor="w", pady=(6,0))
            return val

        self._m_score   = metric_tile(0, "SPAM SCORE")
        self._m_state   = metric_tile(1, "DFA STATE")
        self._m_kw      = metric_tile(2, "KW SIGNALS")
        self._m_rx      = metric_tile(3, "PATTERNS")

        # ── Row 1: verdict card ───────────────────────────────────────────
        self._vdict_outer, self._vdict_inner = card(parent, bg=CARD)
        self._vdict_outer.grid(row=1, column=0, columnspan=4,
                               sticky="nsew", pady=(0, GAP))
        self._verdict_content()   # idle state

        # ── Row 2: findings card ──────────────────────────────────────────
        self._find_outer, self._find_inner = card(parent, bg=CARD)
        self._find_outer.grid(row=2, column=0, columnspan=4, sticky="nsew")
        self._findings_idle()

    # ── Verdict card content ──────────────────────────────────────────────────

    def _verdict_content(self, r=None):
        """Replace verdict card content. Call with r=None for idle state."""
        for w in self._vdict_inner.winfo_children():
            w.destroy()

        if r is None:
            # Idle
            f = tk.Frame(self._vdict_inner, bg=CARD, padx=P, pady=P)
            f.pack(fill="both", expand=True)
            tk.Label(f, text="—", font=F["verdict"],
                     bg=CARD, fg=MUTED).pack(side="left", anchor="w")
            tk.Label(f, text="Run an analysis to see the verdict.",
                     font=F["sm"], bg=CARD, fg=MUTED).pack(
                         side="left", anchor="s", padx=(16,0), pady=(0,6))
            return

        fg, bg, bdr = V[r["verdict"]]
        # Change card bg
        self._vdict_inner.configure(bg=bg)
        self._vdict_outer.configure(bg=bdr)

        f = tk.Frame(self._vdict_inner, bg=bg, padx=P, pady=16)
        f.pack(fill="both", expand=True)

        left = tk.Frame(f, bg=bg)
        left.pack(side="left", fill="y")

        # Dot + verdict text
        dot_row = tk.Frame(left, bg=bg)
        dot_row.pack(anchor="w")
        cv = tk.Canvas(dot_row, width=12, height=12,
                       bg=bg, highlightthickness=0)
        cv.pack(side="left", pady=6, padx=(0,10))
        cv.create_oval(0,0,12,12, fill=fg, outline="")
        tk.Label(dot_row, text=r["verdict"], font=F["verdict"],
                 bg=bg, fg=fg).pack(side="left")

        subtitles = {"SPAM":"High likelihood — do not interact.",
                     "SUSPICIOUS":"Caution — review carefully.",
                     "SAFE":"No significant signals detected."}
        tk.Label(left, text=subtitles[r["verdict"]],
                 font=F["sm"], bg=bg, fg=fg).pack(anchor="w", pady=(4,0))

        # Accepted badge on the right
        right = tk.Frame(f, bg=bg)
        right.pack(side="right", anchor="center")
        acc_lbl = "DFA ACCEPTED" if r["accepted"] else "NOT ACCEPTED"
        acc_col = fg if r["accepted"] else MUTED
        tk.Label(right, text=acc_lbl, font=F["label"],
                 bg=bg, fg=acc_col).pack(anchor="e")
        tk.Label(right, text=r["state"],
                 font=("Consolas",14,"bold"), bg=bg, fg=acc_col).pack(anchor="e")

    # ── Findings card content ─────────────────────────────────────────────────

    def _findings_idle(self):
        for w in self._find_inner.winfo_children():
            w.destroy()
        self._find_inner.configure(bg=CARD)
        self._find_outer.configure(bg=BORDER)

        f = tk.Frame(self._find_inner, bg=CARD, padx=P, pady=P)
        f.pack(fill="both", expand=True)
        tk.Label(f, text="FINDINGS", font=F["label"],
                 bg=CARD, fg=MUTED).pack(anchor="w")
        tk.Label(f, text="No data yet.",
                 font=F["sm"], bg=CARD, fg=MUTED).pack(anchor="w", pady=(8,0))

    def _findings_result(self, r):
        for w in self._find_inner.winfo_children():
            w.destroy()
        self._find_inner.configure(bg=CARD)
        self._find_outer.configure(bg=BORDER)

        if not r["kw"] and not r["rx"]:
            self._findings_idle(); return

        # Header
        hf = tk.Frame(self._find_inner, bg=CARD, padx=P)
        hf.pack(fill="x", pady=(14,0))
        tk.Label(hf, text="FINDINGS", font=F["label"],
                 bg=CARD, fg=MUTED).pack(side="left")
        tk.Frame(hf, bg=BORDER, height=1).pack(
            side="left", fill="x", expand=True, padx=(10,0))

        # Scrollable area
        sf = tk.Frame(self._find_inner, bg=CARD)
        sf.pack(fill="both", expand=True)

        cv = tk.Canvas(sf, bg=CARD, highlightthickness=0,
                       yscrollcommand=lambda *a: sb.set(*a))
        sb = tk.Scrollbar(sf, orient="vertical", command=cv.yview, width=6)
        sb.pack(side="right", fill="y")
        cv.pack(side="left", fill="both", expand=True)

        inner = tk.Frame(cv, bg=CARD)
        wid   = cv.create_window(0, 0, anchor="nw", window=inner)
        cv.bind("<Configure>", lambda e: cv.itemconfig(wid, width=e.width))
        inner.bind("<Configure>",
                   lambda e: cv.configure(scrollregion=cv.bbox("all")))
        cv.bind_all("<MouseWheel>",
                    lambda e: cv.yview_scroll(-(e.delta//120), "units"))

        fg_v = V[r["verdict"]][0]
        px = dict(padx=P)

        # — Keyword rows
        if r["kw"]:
            for cat, words in r["kw"].items():
                row = tk.Frame(inner, bg=CARD_H,
                               highlightbackground=BORDER,
                               highlightthickness=1)
                row.pack(fill="x", pady=(8,0), **px)
                top = tk.Frame(row, bg=CARD_H, padx=14, pady=10)
                top.pack(fill="x")
                tk.Label(top, text=cat, font=F["body_b"],
                         bg=CARD_H, fg=TEXT).pack(side="left")
                # count pill
                cp = tk.Frame(top, bg=MUTED, padx=6, pady=2)
                cp.pack(side="right")
                tk.Label(cp, text=str(len(words)), font=F["xs"],
                         bg=MUTED, fg=TEXT).pack()
                # words as dot-separated mono string
                wstr = "  ·  ".join(words[:6])
                if len(words) > 6: wstr += f"  +{len(words)-6}"
                bot = tk.Frame(row, bg=CARD_H, padx=14)
                bot.pack(fill="x")
                tk.Label(bot, text=wstr, font=F["mono"],
                         bg=CARD_H, fg=MUTED).pack(
                             anchor="w", pady=(0,10))

        # — Regex rows
        if r["rx"]:
            ph = tk.Frame(inner, bg=CARD, padx=P)
            ph.pack(fill="x", pady=(16,4))
            tk.Label(ph, text="PATTERNS", font=F["label"],
                     bg=CARD, fg=MUTED).pack(side="left")
            tk.Frame(ph, bg=BORDER, height=1).pack(
                side="left", fill="x", expand=True, padx=(10,0))

            for lbl, n in r["rx"]:
                row = tk.Frame(inner, bg=CARD_H,
                               highlightbackground=BORDER,
                               highlightthickness=1)
                row.pack(fill="x", pady=(4,0), **px)
                ir = tk.Frame(row, bg=CARD_H, padx=14, pady=9)
                ir.pack(fill="x")
                tk.Label(ir, text=lbl, font=F["body"],
                         bg=CARD_H, fg=TEXT).pack(side="left")
                tk.Label(ir, text=f"×{n}", font=F["mono"],
                         bg=CARD_H, fg=DIM).pack(side="right")

        tk.Frame(inner, bg=CARD, height=16).pack()

    # ── Metric helpers ────────────────────────────────────────────────────────

    def _set_metric(self, lbl_widget, text, color=TEXT):
        lbl_widget.configure(text=text, fg=color)

    def _animate_metric(self, lbl, target, color, unit="%", step=0, frames=36):
        t = 1-(1-step/frames)**3
        lbl.configure(text=f"{int(target*t)}{unit}", fg=color)
        if step < frames:
            self.after(14, lambda: self._animate_metric(
                lbl, target, color, unit, step+1, frames))

    # ── Placeholder ───────────────────────────────────────────────────────────

    def _ph_clear(self):
        if self.txt.get("1.0","end-1c") == self.PH:
            self.txt.delete("1.0","end"); self.txt.configure(fg=TEXT)

    def _ph_restore(self):
        if not self.txt.get("1.0","end-1c").strip():
            self.txt.insert("1.0", self.PH); self.txt.configure(fg=MUTED)

    # ── Samples ───────────────────────────────────────────────────────────────

    def _sample_spam(self):
        self._set_txt(
            "DEAR USER!! You have WON a $1,000,000 LOTTERY PRIZE!\n"
            "Click here to CLAIM NOW and verify your account immediately.\n"
            "LIMITED TIME offer – ACT NOW before it expires!\n"
            "Download now FREE software to activate your reward.\n"
            "Wire transfer details required. Respond immediately.\n"
            "Visit: https://claim-prize.free.net/verify?id=12345678901234\n"
            "Unsubscribe | Risk free trial | 100% Safe Guaranteed!!")

    def _sample_safe(self):
        self._set_txt(
            "Hi Alex,\n\nI hope you're doing well. Please find attached the meeting "
            "notes from yesterday's discussion.\n\nThe team meeting is Thursday at "
            "3 PM in conference room B. Bring your laptop and quarterly report.\n\n"
            "Best regards,\nSarah\nProject Manager")

    def _set_txt(self, t):
        self.txt.configure(fg=TEXT)
        self.txt.delete("1.0","end")
        self.txt.insert("1.0", t)

    # ── Clear ─────────────────────────────────────────────────────────────────

    def _clear(self):
        self.txt.delete("1.0","end"); self._ph_restore()
        for m in [self._m_score, self._m_state, self._m_kw, self._m_rx]:
            m.configure(text="—", fg=MUTED)
        self._verdict_content(None)
        self._findings_idle()
        self.dfa.reset()

    # ── Scan bar ──────────────────────────────────────────────────────────────

    def _scan_tick(self, i=0):
        if not self._scanning: return
        cols = [BLUE,BLUE_D,BORDER2,BORDER,BORDER2,BLUE_D]
        self._scanbar.configure(bg=cols[i%len(cols)])
        self.after(50, lambda: self._scan_tick(i+1))

    # ── Run ───────────────────────────────────────────────────────────────────

    def _run(self):
        text = self.txt.get("1.0","end-1c").strip()
        if not text or text == self.PH:
            messagebox.showwarning("Empty","Paste an email first.", parent=self)
            return
        self._scanning = True
        self.btn.configure(text="Analyzing…", state="disabled", bg=MUTED)
        self._scan_tick()
        self.after(520, lambda: self._finish(text))

    def _finish(self, text):
        self._scanning = False
        self._scanbar.configure(bg=BORDER)
        self.btn.configure(text="Analyze", state="normal", bg=BLUE)

        r = run_analysis(text)
        fg = V[r["verdict"]][0]

        # Animate score metric
        self._animate_metric(self._m_score, r["score"], fg, "%")
        # Set others immediately
        self._set_metric(self._m_state, r["state"], fg)
        self._set_metric(self._m_kw,    str(r["nkw"]), TEXT)
        self._set_metric(self._m_rx,    str(len(r["rx"])), TEXT)

        self._verdict_content(r)
        self._findings_result(r)

        self.dfa.reset()
        self.after(180, lambda: self.dfa.animate(r["state"]))

    # ── Footer ────────────────────────────────────────────────────────────────

    def _footer(self):
        tk.Frame(self, bg=BORDER, height=1).pack(fill="x")
        foot = tk.Frame(self, bg=CARD, height=50)
        foot.pack(fill="x")
        foot.pack_propagate(False)
        inner = tk.Frame(foot, bg=CARD)
        inner.pack(fill="both", expand=True, padx=24)
        self.dfa = DFAStrip(inner)
        self.dfa.pack(side="left", pady=6)
        tk.Label(inner,
                 text="Moniza Fatima  ·  Laraib Suikarno  ·  Miss Alisha Farmaan",
                 font=F["xs"], bg=CARD, fg=MUTED).pack(side="right", pady=17)


if __name__ == "__main__":
    App().mainloop()
