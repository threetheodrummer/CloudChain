import csv, os, matplotlib
R=os.path.join(os.path.dirname(os.path.abspath(__file__)),"..","experiments","results")
matplotlib.use("Agg")
import matplotlib.pyplot as plt
plt.rcParams.update({"font.family":"serif","font.size":7.5,"axes.linewidth":0.6,
    "axes.edgecolor":"#888888","xtick.color":"#444444","ytick.color":"#444444",
    "axes.labelcolor":"#222222","pdf.fonttype":42})
C=["#2a78d6","#eb6834","#1baf7a"]
sc=[r for r in csv.DictReader(open(os.path.join(R,"scalability.csv"))) if r["search"]=="hop_limit_6"]
st=list(csv.DictReader(open(os.path.join(R,"stress_hop_limit.csv"))))
fig,(a,b)=plt.subplots(1,2,figsize=(3.5,1.65))
x=[int(r["identities"]) for r in sc]; y=[float(r["median_seconds"]) for r in sc]
a.plot(x,y,color=C[0],lw=1.4,marker="o",ms=3.5)
a.set_xscale("log"); a.set_yscale("log")
a.set_xlabel("Identities (3 accounts)"); a.set_ylabel("Analysis time (s)")
a.set_title("(a) Synthetic organisations",fontsize=7.5)
a.annotate(f"{y[-1]:.1f} s",(x[-1],y[-1]),textcoords="offset points",xytext=(-22,-9),fontsize=6.5,color="#222222")
for i,(lab,name,m) in enumerate([("hop_limit_4","limit 4","s"),("hop_limit_6","limit 6","o"),("unbounded","unbounded","^")]):
    pts=[(int(r["identities"]),float(r["seconds"])) for r in st if r["search"]==lab and r["status"]=="ok"]
    b.plot(*zip(*pts),color=C[i],lw=1.4,marker=m,ms=3.5,label=name)
b.axhline(60,color="#888888",lw=0.6,ls=(0,(2,2)))
b.text(9.6,85,"60 s timeout",fontsize=6.5,color="#555555")
b.plot([10],[60],marker="x",color=C[2],ms=5,mew=1.4,ls="none")
b.set_yscale("log"); b.set_xlabel("Identities in dense mesh"); b.set_title("(b) Worst case",fontsize=7.5)
b.set_ylim(1e-3,300); b.set_xticks(range(6,13,2))
b.legend(frameon=False,fontsize=6.5,loc="upper left",handlelength=1.4,borderaxespad=0.1)
for ax in (a,b):
    ax.grid(True,which="major",color="#e6e6e6",lw=0.5); ax.set_axisbelow(True)
    for s in ("top","right"): ax.spines[s].set_visible(False)
fig.tight_layout(pad=0.3,w_pad=0.8)
OUT=os.path.dirname(os.path.abspath(__file__))
fig.savefig(os.path.join(OUT,"fig_scalability.pdf"))
