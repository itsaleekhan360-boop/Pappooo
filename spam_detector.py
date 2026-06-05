"""SpamGuard — Theory of Automata | IQRA University"""
import tkinter as tk, re
from tkinter import messagebox

# ── Engine ────────────────────────────────────────────────────────────────────
KW = {
    "Financial Scam": ["free money","you won","prize","lottery","claim now","bank account","wire transfer","cash prize","million dollars","inheritance","winner","jackpot"],
    "Phishing":       ["verify your account","click here","update your password","confirm your email","login now","suspended account","unusual activity","reset your password","verify immediately"],
    "Malware":        ["download now","free software","crack version","keygen","activate now","serial key","patch download"],
    "Urgency":        ["act now","limited time","expires soon","urgent","last chance","immediate action","respond immediately","deadline today"],
    "Adult Content":  ["adult content","18+","hot singles","meet girls","dating site"],
    "Fake Health":    ["lose weight fast","miracle cure","diet pill","guaranteed results","risk free trial","100% safe","doctors hate"],
}
RX = [
    (r"\b[A-Z]{4,}\b","ALL-CAPS words"),(r"!{2,}","Multiple !!"),
    (r"\$\d+","Dollar amount"),(r"https?://\S+","URL link"),
    (r"\b\d{10,}\b","Long number"),(r"(?i)\bfree\b","Word: free"),
    (r"(?i)\bgift\b","Keyword: gift"),(r"(?i)\boffer\b","Keyword: offer"),
    (r"(?i)dear\s+(sir|madam|friend|user)","Generic salutation"),
    (r"(?i)\bunsubscribe\b","Unsubscribe link"),
]

class DFA:
    T = {("q0",0):"q0",("q0",1):"q1",("q1",1):"q1",("q1",2):"q2",
         ("q2",1):"q2",("q2",2):"q3",("q3",1):"q3",("q3",2):"q3"}
    def run(self, n):
        s = "q0"
        while n > 0: step=min(n,2); s=self.T.get((s,step),s); n-=step
        return s

def analyse(text):
    tl = text.lower(); kw = {}; nkw = 0
    for cat, words in KW.items():
        f = [w for w in words if w in tl]
        if f: kw[cat]=f; nkw+=len(f)
    rx  = [(l,c) for l,c in ((l,len(re.findall(p,text))) for p,l in RX) if c]
    st  = DFA().run(nkw); acc = st=="q3"
    sc  = min(int(((nkw+len(rx)*.5)/20)*100),100)
    if acc and sc<70: sc=70
    vrd = "SPAM" if sc>=60 or acc else "SUSPICIOUS" if sc>=30 else "SAFE"
    return dict(verdict=vrd,score=sc,state=st,accepted=acc,kw=kw,nkw=nkw,rx=rx)

# ── Design tokens ─────────────────────────────────────────────────────────────
BG,CARD,CARD_H = "#0C0C0E","#131316","#1A1A1E"
BORDER,BORDER2  = "#242428","#2E2E34"
BLUE,BLUE_D     = "#5865F2","#4752C4"
TEXT,DIM,MUTED  = "#EFEFEF","#888896","#3E3E48"
V = {"SPAM":("#F04747","#160A0A","#3A1212"),
     "SUSPICIOUS":("#F5A623","#160F04","#3A2808"),
     "SAFE":("#23D160","#05140C","#0E3320")}
DC = {"q0":"#818CF8","q1":"#38BDF8","q2":"#FBBF24","q3":"#F04747"}
F  = {"nav":("Segoe UI",11,"bold"),"lbl":("Segoe UI",8,"bold"),
      "body":("Segoe UI",10),"bb":("Segoe UI",10,"bold"),
      "sm":("Segoe UI",9),"xs":("Segoe UI",8),
      "mono":("Consolas",9),"lg":("Segoe UI",20,"bold"),
      "vrd":("Segoe UI",28,"bold")}
G,P = 8,18

def mk_card(parent, bg=None, bdr=None):
    bg=bg or CARD; bdr=bdr or BORDER
    o=tk.Frame(parent,bg=bdr,padx=1,pady=1)
    i=tk.Frame(o,bg=bg); i.pack(fill="both",expand=True)
    return o,i

# ── DFA strip ─────────────────────────────────────────────────────────────────
class DFAStrip(tk.Canvas):
    NODES=["q0","q1","q2","q3"]; NR=13; GN=90; H=50
    def __init__(self,parent,**kw):
        W=len(self.NODES)*self.NR*2+(len(self.NODES)-1)*self.GN+80
        super().__init__(parent,width=W,height=self.H,bg=CARD,highlightthickness=0,**kw)
        self._lit=set(); self._draw()
    def _cx(self,i):
        sp=(len(self.NODES)-1)*self.GN; st=(int(self["width"])-sp)//2
        return st+i*self.GN
    def _draw(self):
        self.delete("all"); cy=self.H//2; xs=[self._cx(i) for i in range(4)]
        for i in range(3):
            a,b=self.NODES[i],self.NODES[i+1]
            self.create_line(xs[i]+self.NR,cy,xs[i+1]-self.NR,cy,
                             fill=DC[a] if(a in self._lit and b in self._lit)else BORDER2,width=1)
        x3=xs[3]; lit3="q3" in self._lit
        self.create_arc(x3-15,cy-24,x3+15,cy-2,start=20,extent=200,style="arc",
                        outline=DC["q3"] if lit3 else MUTED,width=1)
        for i,s in enumerate(self.NODES):
            x=xs[i]; lit=s in self._lit; nc=DC[s]
            if s=="q3": self.create_oval(x-self.NR-4,cy-self.NR-4,x+self.NR+4,cy+self.NR+4,
                                         outline=nc if lit else MUTED,width=1,dash=(3,3))
            self.create_oval(x-self.NR,cy-self.NR,x+self.NR,cy+self.NR,
                             fill=CARD_H if lit else CARD,outline=nc if lit else MUTED,width=2 if lit else 1)
            self.create_text(x,cy,text=s,font=("Consolas",8,"bold"),fill=nc if lit else DIM)
        cur=max(self._lit,key=lambda s:self.NODES.index(s)) if self._lit else None
        self.create_text(int(self["width"])-12,cy,text=f"state  {cur or '—'}",
                         font=("Consolas",8),fill=DIM,anchor="e")
    def animate(self,final,step=0):
        idx=self.NODES.index(final)
        if step<=idx:
            self._lit=set(self.NODES[:step+1]); self._draw()
            self.after(240,lambda:self.animate(final,step+1))
    def reset(self): self._lit=set(); self._draw()

# ── App ───────────────────────────────────────────────────────────────────────
class App(tk.Tk):
    PH = "Paste the full email body here…"
    def __init__(self):
        super().__init__()
        self.title("SpamGuard — Theory of Automata  |  IQRA University")
        self.configure(bg=BG); self.geometry("1180x720"); self.minsize(980,600)
        self._scanning=False; self._build()

    def _build(self):
        # Nav
        n=tk.Frame(self,bg=CARD,height=46); n.pack(fill="x"); n.pack_propagate(False)
        tk.Frame(self,bg=BORDER,height=1).pack(fill="x")
        f=tk.Frame(n,bg=CARD); f.pack(fill="both",expand=True,padx=24)
        lg=tk.Frame(f,bg=CARD); lg.pack(side="left",pady=11)
        self._dot=tk.Canvas(lg,width=8,height=8,bg=CARD,highlightthickness=0)
        self._dot.pack(side="left",padx=(0,9)); self._dot_on=True; self._breathe()
        tk.Label(lg,text="SpamGuard",font=F["nav"],bg=CARD,fg=TEXT).pack(side="left")
        tk.Label(lg,text="  /  Theory of Automata",font=F["body"],bg=CARD,fg=DIM).pack(side="left")
        tk.Label(f,text="IQRA University  ·  DFA + Regex",font=F["xs"],bg=CARD,fg=MUTED).pack(side="right",pady=16)

        # Body
        body=tk.Frame(self,bg=BG); body.pack(fill="both",expand=True)
        lw=tk.Frame(body,bg=BG,width=460); lw.pack(side="left",fill="y",padx=(G,0),pady=G); lw.pack_propagate(False)
        self._left(lw)
        rw=tk.Frame(body,bg=BG); rw.pack(side="left",fill="both",expand=True,padx=G,pady=G)
        self._bento(rw)

        # Footer
        tk.Frame(self,bg=BORDER,height=1).pack(fill="x")
        ft=tk.Frame(self,bg=CARD,height=50); ft.pack(fill="x"); ft.pack_propagate(False)
        fi=tk.Frame(ft,bg=CARD); fi.pack(fill="both",expand=True,padx=24)
        self.dfa=DFAStrip(fi); self.dfa.pack(side="left",pady=6)
        tk.Label(fi,text="Moniza Fatima  ·  Laraib Suikarno  ·  Miss Alisha Farmaan",
                 font=F["xs"],bg=CARD,fg=MUTED).pack(side="right",pady=17)

    def _breathe(self):
        self._dot_on=not self._dot_on
        self._dot.delete("all")
        self._dot.create_oval(0,0,8,8,fill=BLUE if self._dot_on else BLUE_D,outline="")
        self.after(900,self._breathe)

    def _left(self,parent):
        lf=tk.Frame(parent,bg=BG); lf.pack(fill="x",pady=(0,G))
        tk.Label(lf,text="EMAIL BODY",font=F["lbl"],bg=BG,fg=MUTED).pack(side="left")
        self._tb=tk.Frame(parent,bg=BORDER,padx=1,pady=1); self._tb.pack(fill="both",expand=True)
        self.txt=tk.Text(self._tb,wrap="word",font=F["mono"],bg=CARD,fg=TEXT,
                         insertbackground=BLUE,selectbackground=BORDER2,selectforeground=TEXT,
                         relief="flat",bd=0,padx=16,pady=14,spacing1=3,spacing3=3,undo=True)
        self.txt.pack(fill="both",expand=True)
        self.txt.insert("1.0",self.PH); self.txt.configure(fg=MUTED)
        self.txt.bind("<FocusIn>", lambda e:[self._phc(), self._tb.configure(bg=BLUE)])
        self.txt.bind("<FocusOut>",lambda e:[self._phr(), self._tb.configure(bg=BORDER)])
        self._sb=tk.Frame(parent,bg=BORDER,height=2); self._sb.pack(fill="x")
        bf=tk.Frame(parent,bg=BG); bf.pack(fill="x",pady=(G,0))
        self.btn=tk.Button(bf,text="Analyze",command=self._run,font=F["bb"],
                           bg=BLUE,fg="white",activebackground=BLUE_D,activeforeground="white",
                           relief="flat",cursor="hand2",padx=20,pady=9,bd=0)
        self.btn.pack(side="left")
        for t,c in [("Spam sample",self._spam),("Safe sample",self._safe)]:
            tk.Button(bf,text=t,command=c,font=F["body"],bg=CARD_H,fg=DIM,
                      activebackground=BORDER2,activeforeground=TEXT,relief="flat",
                      cursor="hand2",padx=14,pady=9,bd=0,
                      highlightbackground=BORDER,highlightthickness=1).pack(side="left",padx=(G,0))
        tk.Button(bf,text="Clear",command=self._clear,font=F["body"],bg=BG,fg=MUTED,
                  activebackground=BG,activeforeground=DIM,relief="flat",
                  cursor="hand2",padx=12,pady=9,bd=0).pack(side="right")

    def _bento(self,p):
        for c in range(4): p.columnconfigure(c,weight=1,uniform="c")
        p.rowconfigure(0,weight=0); p.rowconfigure(1,weight=0); p.rowconfigure(2,weight=1)
        self._ms=[]
        for col,lbl in enumerate(["SPAM SCORE","DFA STATE","KW SIGNALS","PATTERNS"]):
            o,i=mk_card(p)
            o.grid(row=0,column=col,sticky="nsew",pady=(0,G),
                   padx=(0 if col==0 else G//2, 0 if col==3 else G//2))
            ip=tk.Frame(i,bg=CARD,padx=P,pady=16); ip.pack(fill="both",expand=True)
            tk.Label(ip,text=lbl,font=F["lbl"],bg=CARD,fg=MUTED).pack(anchor="w")
            v=tk.Label(ip,text="—",font=F["lg"],bg=CARD,fg=MUTED); v.pack(anchor="w",pady=(6,0))
            self._ms.append(v)
        self._vo,self._vi=mk_card(p)
        self._vo.grid(row=1,column=0,columnspan=4,sticky="nsew",pady=(0,G))
        self._verdict()
        self._fo,self._fi=mk_card(p)
        self._fo.grid(row=2,column=0,columnspan=4,sticky="nsew")
        self._findings()

    def _verdict(self,r=None):
        for w in self._vi.winfo_children(): w.destroy()
        if r is None:
            f=tk.Frame(self._vi,bg=CARD,padx=P,pady=P); f.pack(fill="both",expand=True)
            tk.Label(f,text="—",font=F["vrd"],bg=CARD,fg=MUTED).pack(side="left",anchor="w")
            tk.Label(f,text="Run an analysis to see the verdict.",font=F["sm"],bg=CARD,fg=MUTED).pack(
                side="left",anchor="s",padx=(16,0),pady=(0,6))
            self._vi.configure(bg=CARD); self._vo.configure(bg=BORDER); return
        fg,bg,bdr=V[r["verdict"]]
        self._vi.configure(bg=bg); self._vo.configure(bg=bdr)
        f=tk.Frame(self._vi,bg=bg,padx=P,pady=16); f.pack(fill="both",expand=True)
        lf=tk.Frame(f,bg=bg); lf.pack(side="left",fill="y")
        dr=tk.Frame(lf,bg=bg); dr.pack(anchor="w")
        cv=tk.Canvas(dr,width=12,height=12,bg=bg,highlightthickness=0)
        cv.pack(side="left",pady=6,padx=(0,10)); cv.create_oval(0,0,12,12,fill=fg,outline="")
        tk.Label(dr,text=r["verdict"],font=F["vrd"],bg=bg,fg=fg).pack(side="left")
        subs={"SPAM":"High likelihood — do not interact.","SUSPICIOUS":"Caution — review carefully.","SAFE":"No significant signals detected."}
        tk.Label(lf,text=subs[r["verdict"]],font=F["sm"],bg=bg,fg=fg).pack(anchor="w",pady=(4,0))
        rf=tk.Frame(f,bg=bg); rf.pack(side="right",anchor="center")
        ac="DFA ACCEPTED" if r["accepted"] else "NOT ACCEPTED"; acc=fg if r["accepted"] else MUTED
        tk.Label(rf,text=ac,font=F["lbl"],bg=bg,fg=acc).pack(anchor="e")
        tk.Label(rf,text=r["state"],font=("Consolas",14,"bold"),bg=bg,fg=acc).pack(anchor="e")

    def _findings(self,r=None):
        for w in self._fi.winfo_children(): w.destroy()
        self._fi.configure(bg=CARD); self._fo.configure(bg=BORDER)
        if r is None or (not r["kw"] and not r["rx"]):
            f=tk.Frame(self._fi,bg=CARD,padx=P,pady=P); f.pack(fill="both",expand=True)
            tk.Label(f,text="FINDINGS",font=F["lbl"],bg=CARD,fg=MUTED).pack(anchor="w")
            tk.Label(f,text="No data yet." if r is None else "No signals found.",
                     font=F["sm"],bg=CARD,fg=MUTED).pack(anchor="w",pady=(8,0)); return
        hf=tk.Frame(self._fi,bg=CARD,padx=P); hf.pack(fill="x",pady=(14,0))
        tk.Label(hf,text="FINDINGS",font=F["lbl"],bg=CARD,fg=MUTED).pack(side="left")
        tk.Frame(hf,bg=BORDER,height=1).pack(side="left",fill="x",expand=True,padx=(10,0))
        sf=tk.Frame(self._fi,bg=CARD); sf.pack(fill="both",expand=True)
        cv=tk.Canvas(sf,bg=CARD,highlightthickness=0,yscrollcommand=lambda *a:sb.set(*a))
        sb=tk.Scrollbar(sf,orient="vertical",command=cv.yview,width=6)
        sb.pack(side="right",fill="y"); cv.pack(side="left",fill="both",expand=True)
        inn=tk.Frame(cv,bg=CARD); wid=cv.create_window(0,0,anchor="nw",window=inn)
        cv.bind("<Configure>",lambda e:cv.itemconfig(wid,width=e.width))
        inn.bind("<Configure>",lambda e:cv.configure(scrollregion=cv.bbox("all")))
        cv.bind_all("<MouseWheel>",lambda e:cv.yview_scroll(-(e.delta//120),"units"))
        px=dict(padx=P)
        for cat,words in r["kw"].items():
            row=tk.Frame(inn,bg=CARD_H,highlightbackground=BORDER,highlightthickness=1)
            row.pack(fill="x",pady=(8,0),**px)
            top=tk.Frame(row,bg=CARD_H,padx=14,pady=10); top.pack(fill="x")
            tk.Label(top,text=cat,font=F["bb"],bg=CARD_H,fg=TEXT).pack(side="left")
            cp=tk.Frame(top,bg=MUTED,padx=6,pady=2); cp.pack(side="right")
            tk.Label(cp,text=str(len(words)),font=F["xs"],bg=MUTED,fg=TEXT).pack()
            bot=tk.Frame(row,bg=CARD_H,padx=14); bot.pack(fill="x")
            wstr="  ·  ".join(words[:6])+(f"  +{len(words)-6}" if len(words)>6 else "")
            tk.Label(bot,text=wstr,font=F["mono"],bg=CARD_H,fg=MUTED).pack(anchor="w",pady=(0,10))
        if r["rx"]:
            ph=tk.Frame(inn,bg=CARD,padx=P); ph.pack(fill="x",pady=(16,4))
            tk.Label(ph,text="PATTERNS",font=F["lbl"],bg=CARD,fg=MUTED).pack(side="left")
            tk.Frame(ph,bg=BORDER,height=1).pack(side="left",fill="x",expand=True,padx=(10,0))
            for lbl,n in r["rx"]:
                row=tk.Frame(inn,bg=CARD_H,highlightbackground=BORDER,highlightthickness=1)
                row.pack(fill="x",pady=(4,0),**px)
                ir=tk.Frame(row,bg=CARD_H,padx=14,pady=9); ir.pack(fill="x")
                tk.Label(ir,text=lbl,font=F["body"],bg=CARD_H,fg=TEXT).pack(side="left")
                tk.Label(ir,text=f"×{n}",font=F["mono"],bg=CARD_H,fg=DIM).pack(side="right")
        tk.Frame(inn,bg=CARD,height=16).pack()

    def _phc(self):
        if self.txt.get("1.0","end-1c")==self.PH: self.txt.delete("1.0","end"); self.txt.configure(fg=TEXT)
    def _phr(self):
        if not self.txt.get("1.0","end-1c").strip(): self.txt.insert("1.0",self.PH); self.txt.configure(fg=MUTED)
    def _set(self,t):
        self.txt.configure(fg=TEXT); self.txt.delete("1.0","end"); self.txt.insert("1.0",t)
    def _spam(self): self._set("DEAR USER!! You have WON a $1,000,000 LOTTERY PRIZE!\nClick here to CLAIM NOW and verify your account immediately.\nLIMITED TIME offer – ACT NOW before it expires!\nDownload now FREE software to activate your reward.\nWire transfer details required. Respond immediately.\nVisit: https://claim-prize.free.net/verify?id=12345678901234\nUnsubscribe | Risk free trial | 100% Safe Guaranteed!!")
    def _safe(self):  self._set("Hi Alex,\n\nI hope you're doing well. Please find attached the meeting notes from yesterday's discussion.\n\nThe team meeting is Thursday at 3 PM in conference room B. Bring your laptop and quarterly report.\n\nBest regards,\nSarah\nProject Manager")
    def _clear(self):
        self.txt.delete("1.0","end"); self._phr()
        for m in self._ms: m.configure(text="—",fg=MUTED)
        self._verdict(); self._findings(); self.dfa.reset()
    def _tick(self,i=0):
        if not self._scanning: return
        self._sb.configure(bg=[BLUE,BLUE_D,BORDER2,BORDER,BORDER2,BLUE_D][i%6])
        self.after(50,lambda:self._tick(i+1))
    def _run(self):
        text=self.txt.get("1.0","end-1c").strip()
        if not text or text==self.PH: messagebox.showwarning("Empty","Paste an email first.",parent=self); return
        self._scanning=True; self.btn.configure(text="Analyzing…",state="disabled",bg=MUTED); self._tick()
        self.after(520,lambda:self._done(text))
    def _anim(self,lbl,target,color,step=0,frames=36):
        lbl.configure(text=f"{int(target*(1-(1-step/frames)**3))}%",fg=color)
        if step<frames: self.after(14,lambda:self._anim(lbl,target,color,step+1,frames))
    def _done(self,text):
        self._scanning=False; self._sb.configure(bg=BORDER)
        self.btn.configure(text="Analyze",state="normal",bg=BLUE)
        r=analyse(text); fg=V[r["verdict"]][0]
        self._anim(self._ms[0],r["score"],fg)
        self._ms[1].configure(text=r["state"],fg=fg)
        self._ms[2].configure(text=str(r["nkw"]),fg=TEXT)
        self._ms[3].configure(text=str(len(r["rx"])),fg=TEXT)
        self._verdict(r); self._findings(r)
        self.dfa.reset(); self.after(180,lambda:self.dfa.animate(r["state"]))

if __name__=="__main__": App().mainloop()
