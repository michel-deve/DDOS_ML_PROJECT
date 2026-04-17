from flask import Flask, jsonify, render_template_string, request
from flask_cors import CORS
import os, json, time, threading
from collections import deque
from datetime import datetime

app = Flask(__name__)
CORS(app)

BLOCKED_IPS_FILE = "blocked_ips.json"

state = {
    "under_attack": False,
    "packets_per_sec": 0,
    "total_packets_received": 0,
    "total_blocked": 0,
    "blocked_ips": {},
    "rate_history": deque(maxlen=30),
    "status": "healthy",
    "_new_ips": set(),
    "_prev_blocked": set(),
}
lock = threading.Lock()

def sync_blocked():
    try:
        if os.path.exists(BLOCKED_IPS_FILE):
            with open(BLOCKED_IPS_FILE, "r") as f:
                data = json.load(f)
            with lock:
                new = set(data.keys()) - state["_prev_blocked"]
                state["_new_ips"].update(new)
                state["_prev_blocked"] = set(data.keys())
                state["blocked_ips"] = data
                state["total_blocked"] = len(data)
    except Exception:
        pass

def bg_sync():
    mitigated_since = None
    while True:
        time.sleep(1)
        sync_blocked()
        with lock:
            state["rate_history"].append(state["packets_per_sec"])
            hist = list(state["rate_history"])

            if state["under_attack"] and state["packets_per_sec"] == 0:
                # Attack rate dropped — check if sustained for 2s
                if len(hist) >= 2 and all(r == 0 for r in hist[-2:]):
                    state["under_attack"] = False
                    state["status"] = "mitigated"
                    mitigated_since = time.time()

            elif state["status"] == "mitigated":
                # After 5 seconds of recovery, go back to healthy
                # so the NEXT wave properly triggers 'attacking' again
                if mitigated_since and (time.time() - mitigated_since) > 5:
                    state["status"] = "healthy"
                    mitigated_since = None

            elif not state["under_attack"] and state["packets_per_sec"] == 0:
                state["status"] = "healthy"

threading.Thread(target=bg_sync, daemon=True).start()

# ─── HTML ────────────────────────────────────────────────────────────────
HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Aurora Shop — Live Security Demo</title>
<link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700&display=swap" rel="stylesheet">
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
:root{
  --bg:#060d1a;--s:rgba(255,255,255,.04);--b:rgba(255,255,255,.08);
  --acc:#3b82f6;--acc2:#06b6d4;--g:#10b981;--r:#ef4444;--y:#f59e0b;
  --tx:#f1f5f9;--mt:#64748b;
}
*{box-sizing:border-box;margin:0;padding:0;}
body{font-family:'Outfit',sans-serif;background:var(--bg);color:var(--tx);min-height:100vh;transition:background .6s;}
body::before{content:'';position:fixed;top:-20%;left:-10%;width:60vw;height:60vh;
  background:radial-gradient(circle,rgba(59,130,246,.1) 0%,transparent 70%);
  pointer-events:none;z-index:0;transition:background 1s;}
body.att::before{background:radial-gradient(circle,rgba(239,68,68,.18) 0%,transparent 70%);}
body.mit::before{background:radial-gradient(circle,rgba(16,185,129,.12) 0%,transparent 70%);}

/* NAV */
nav{display:flex;align-items:center;justify-content:space-between;padding:1rem 3%;
  border-bottom:1px solid var(--b);background:rgba(6,13,26,.85);
  backdrop-filter:blur(16px);position:sticky;top:0;z-index:60;}
.logo{font-size:1.6rem;font-weight:700;background:linear-gradient(135deg,#60a5fa,#06b6d4);
  -webkit-background-clip:text;color:transparent;}
.nav-center{display:flex;gap:1.5rem;}
.nav-center a{color:var(--mt);text-decoration:none;font-weight:500;font-size:.9rem;
  transition:color .2s;cursor:pointer;}
.nav-center a:hover,.nav-center a.active{color:var(--tx);}
.nav-right{display:flex;align-items:center;gap:1rem;}
.cart-btn{background:var(--s);border:1px solid var(--b);color:var(--tx);
  padding:.45rem 1.1rem;border-radius:8px;cursor:pointer;font-family:inherit;
  font-size:.88rem;font-weight:500;transition:background .2s;}
.cart-btn:hover{background:rgba(255,255,255,.08);}
.cart-count{background:var(--acc);color:#fff;border-radius:99px;
  padding:.1rem .45rem;font-size:.7rem;margin-left:.3rem;}
.pill{display:flex;align-items:center;gap:.45rem;padding:.38rem .9rem;
  border-radius:99px;border:1px solid var(--b);background:var(--s);
  font-size:.8rem;font-weight:600;transition:all .4s;}
.pill.ok{border-color:rgba(16,185,129,.35);color:#6ee7b7;}
.pill.bad{border-color:rgba(239,68,68,.35);color:#fca5a5;}
.pill.mit{border-color:rgba(16,185,129,.35);color:#6ee7b7;}
.dot{width:7px;height:7px;border-radius:50%;background:var(--g);
  box-shadow:0 0 6px var(--g);transition:all .4s;}
.pill.bad .dot{background:var(--r);box-shadow:0 0 8px var(--r);
  animation:blk .5s infinite alternate;}
@keyframes blk{from{opacity:1}to{opacity:.3}}

/* PAGES */
.page{display:none;position:relative;z-index:1;}
.page.active{display:block;}

/* HERO */
.hero{text-align:center;padding:4.5rem 2rem 2.5rem;}
.hero h1{font-size:clamp(2rem,5vw,3.6rem);font-weight:700;line-height:1.15;
  background:linear-gradient(135deg,#f1f5f9 30%,#94a3b8);-webkit-background-clip:text;color:transparent;}
.hero p{color:var(--mt);font-size:1.05rem;max-width:520px;margin:.9rem auto 2rem;}
.hero-cta{display:flex;gap:1rem;justify-content:center;flex-wrap:wrap;}
.btn-pri{background:linear-gradient(135deg,var(--acc),var(--acc2));color:#fff;border:none;
  padding:.8rem 2rem;border-radius:99px;font-weight:600;font-size:.95rem;cursor:pointer;
  box-shadow:0 0 20px rgba(59,130,246,.3);transition:transform .2s,box-shadow .2s;font-family:inherit;}
.btn-pri:hover{transform:translateY(-2px);box-shadow:0 0 30px rgba(59,130,246,.45);}
.btn-sec{background:var(--s);border:1px solid var(--b);color:var(--tx);
  padding:.8rem 2rem;border-radius:99px;font-weight:500;font-size:.95rem;
  cursor:pointer;font-family:inherit;transition:background .2s;}
.btn-sec:hover{background:rgba(255,255,255,.07);}

/* STATS BAR */
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:1rem;padding:0 3% 1.5rem;}
.sc{background:var(--s);border:1px solid var(--b);border-radius:12px;padding:1rem 1.3rem;transition:border-color .4s;}
.sc .lbl{font-size:.72rem;color:var(--mt);text-transform:uppercase;letter-spacing:.07em;}
.sc .val{font-size:1.7rem;font-weight:700;margin:.2rem 0;transition:color .4s;}
.sc .sub{font-size:.72rem;color:var(--mt);}
.sc.danger{border-color:rgba(239,68,68,.4);}.sc.danger .val{color:var(--r);}
.sc.safe .val{color:var(--g);}

/* PRODUCTS LAYOUT */
.shop-layout{display:grid;grid-template-columns:220px 1fr;gap:1.5rem;padding:0 3% 3rem;}
.sidebar{background:var(--s);border:1px solid var(--b);border-radius:14px;padding:1.3rem;
  height:fit-content;position:sticky;top:72px;}
.sidebar h3{font-size:.8rem;color:var(--mt);text-transform:uppercase;letter-spacing:.08em;margin-bottom:1rem;}
.cat-btn{display:block;width:100%;text-align:left;background:none;border:none;color:var(--mt);
  font-family:inherit;font-size:.88rem;padding:.5rem .7rem;border-radius:8px;cursor:pointer;
  transition:all .2s;margin-bottom:.2rem;}
.cat-btn:hover,.cat-btn.active{background:rgba(59,130,246,.12);color:var(--tx);}
.cat-btn.active{color:var(--acc);}
.price-filter{margin-top:1.2rem;}
.price-filter input{width:100%;accent-color:var(--acc);}
.price-range-label{font-size:.8rem;color:var(--mt);margin-top:.4rem;}
.product-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:1.2rem;}
.pc{background:var(--s);border:1px solid var(--b);border-radius:14px;overflow:hidden;
  transition:transform .25s,border-color .25s,opacity .5s,filter .5s;cursor:pointer;}
.pc:hover{transform:translateY(-4px);border-color:rgba(255,255,255,.18);}
.pi{height:150px;display:flex;align-items:center;justify-content:center;
  font-size:3.5rem;background:linear-gradient(135deg,#1e293b,#0f172a);}
.pc-body{padding:1rem;}
.pc-cat{font-size:.68rem;color:var(--acc2);text-transform:uppercase;letter-spacing:.07em;}
.pc-name{font-size:.92rem;font-weight:600;margin:.3rem 0;}
.pc-desc{font-size:.75rem;color:var(--mt);line-height:1.4;margin-bottom:.7rem;}
.pc-footer{display:flex;align-items:center;justify-content:space-between;}
.pc-price{font-size:1.1rem;font-weight:700;color:var(--acc2);}
.add-btn{background:var(--acc);color:#fff;border:none;padding:.4rem .9rem;
  border-radius:8px;font-size:.78rem;font-weight:600;cursor:pointer;
  font-family:inherit;transition:background .2s;}
.add-btn:hover{background:#2563eb;}

/* PRODUCT DETAIL */
.pd-back{background:none;border:1px solid var(--b);color:var(--mt);
  padding:.45rem 1rem;border-radius:8px;font-family:inherit;cursor:pointer;
  margin:1.5rem 3%;font-size:.85rem;transition:all .2s;}
.pd-back:hover{color:var(--tx);border-color:rgba(255,255,255,.2);}
.pd-layout{display:grid;grid-template-columns:1fr 1fr;gap:3rem;padding:1rem 3% 3rem;max-width:900px;}
.pd-img{height:340px;background:linear-gradient(135deg,#1e293b,#0f172a);
  display:flex;align-items:center;justify-content:center;font-size:8rem;
  border-radius:16px;border:1px solid var(--b);}
.pd-info h1{font-size:1.8rem;font-weight:700;margin-bottom:.3rem;}
.pd-badge{display:inline-block;background:rgba(59,130,246,.15);color:var(--acc2);
  font-size:.72rem;font-weight:600;padding:.3rem .8rem;border-radius:99px;
  text-transform:uppercase;letter-spacing:.06em;margin-bottom:.8rem;border:1px solid rgba(59,130,246,.2);}
.pd-price{font-size:2.2rem;font-weight:700;color:var(--acc2);margin:.5rem 0 1rem;}
.pd-desc{color:var(--mt);line-height:1.7;margin-bottom:1.5rem;}
.pd-specs{background:var(--s);border:1px solid var(--b);border-radius:10px;padding:1rem;margin-bottom:1.5rem;}
.pd-spec{display:flex;justify-content:space-between;padding:.4rem 0;
  border-bottom:1px solid var(--b);font-size:.85rem;}
.pd-spec:last-child{border:none;}
.pd-spec-k{color:var(--mt);}
.qty-row{display:flex;align-items:center;gap:1rem;margin-bottom:1rem;}
.qty-btn{background:var(--s);border:1px solid var(--b);color:var(--tx);
  width:34px;height:34px;border-radius:8px;font-size:1.1rem;cursor:pointer;
  font-family:inherit;transition:background .2s;}
.qty-btn:hover{background:rgba(255,255,255,.08);}
.qty-val{font-size:1.1rem;font-weight:600;min-width:2rem;text-align:center;}
.add-to-cart-big{width:100%;padding:1rem;background:linear-gradient(135deg,var(--acc),var(--acc2));
  color:#fff;border:none;border-radius:12px;font-size:1rem;font-weight:700;
  cursor:pointer;font-family:inherit;transition:transform .2s,box-shadow .2s;
  box-shadow:0 0 16px rgba(59,130,246,.25);}
.add-to-cart-big:hover{transform:translateY(-2px);box-shadow:0 0 24px rgba(59,130,246,.4);}

/* CART */
.cart-page{padding:1.5rem 3% 3rem;}
.cart-page h1{font-size:1.8rem;font-weight:700;margin-bottom:1.5rem;}
.cart-empty{text-align:center;padding:4rem;color:var(--mt);}
.cart-empty .ei{font-size:5rem;margin-bottom:1rem;}
.cart-table{width:100%;border-collapse:collapse;}
.cart-table th{font-size:.75rem;color:var(--mt);text-transform:uppercase;
  letter-spacing:.07em;padding:.7rem 1rem;border-bottom:1px solid var(--b);text-align:left;}
.cart-table td{padding:.9rem 1rem;border-bottom:1px solid var(--b);vertical-align:middle;}
.ci-icon{font-size:2rem;}
.ci-name{font-weight:600;font-size:.92rem;}
.ci-cat{font-size:.72rem;color:var(--mt);}
.cart-qty{display:flex;align-items:center;gap:.5rem;}
.cart-qty button{background:var(--s);border:1px solid var(--b);color:var(--tx);
  width:28px;height:28px;border-radius:6px;cursor:pointer;font-size:.9rem;font-family:inherit;}
.rm-btn{background:none;border:none;color:var(--mt);cursor:pointer;font-size:1.1rem;
  transition:color .2s;}
.rm-btn:hover{color:var(--r);}
.cart-summary{background:var(--s);border:1px solid var(--b);border-radius:14px;
  padding:1.5rem;max-width:380px;margin-left:auto;margin-top:1.5rem;}
.cs-row{display:flex;justify-content:space-between;font-size:.9rem;margin:.5rem 0;color:var(--mt);}
.cs-total{display:flex;justify-content:space-between;font-size:1.2rem;font-weight:700;
  margin-top:.8rem;padding-top:.8rem;border-top:1px solid var(--b);}
.checkout-btn{width:100%;margin-top:1rem;padding:.9rem;
  background:linear-gradient(135deg,var(--g),#0891b2);color:#fff;border:none;
  border-radius:10px;font-size:.95rem;font-weight:700;cursor:pointer;font-family:inherit;}

/* MONITOR */
.monitor-page{padding:1.5rem 3% 3rem;}
.monitor-page h1{font-size:1.7rem;font-weight:700;margin-bottom:1.2rem;}
.monitor-grid{display:grid;grid-template-columns:1fr 380px;gap:1.5rem;}
.chart-panel{background:var(--s);border:1px solid var(--b);border-radius:14px;padding:1.5rem;}
.panel-lbl{font-size:.75rem;color:var(--mt);text-transform:uppercase;letter-spacing:.08em;margin-bottom:1rem;}
.log-box{background:var(--s);border:1px solid var(--b);border-radius:14px;padding:1.3rem;
  max-height:400px;overflow-y:auto;}
.log-box::-webkit-scrollbar{width:3px;}
.log-box::-webkit-scrollbar-thumb{background:var(--b);border-radius:3px;}
.le{padding:.3rem 0;border-bottom:1px solid rgba(255,255,255,.04);
  font-size:.75rem;font-family:'Courier New',monospace;color:var(--mt);}
.le.blk{color:#fca5a5;}.le.det{color:#fde68a;}.le.mit{color:#6ee7b7;}.le.norm{color:#93c5fd;}
.blocked-list{margin-top:1.2rem;background:var(--s);border:1px solid var(--b);
  border-radius:14px;padding:1.3rem;}
.bl-item{display:flex;justify-content:space-between;align-items:center;
  padding:.5rem .7rem;border-radius:8px;background:rgba(239,68,68,.06);
  border:1px solid rgba(239,68,68,.15);margin-bottom:.4rem;font-size:.8rem;}
.bl-ip{color:#fca5a5;font-family:'Courier New',monospace;font-weight:600;}
.bl-time{color:var(--mt);font-size:.7rem;}

/* ATTACK WARNING BAR (replaces blocking overlay) */
#attackBar{
  position:fixed;top:0;left:0;right:0;z-index:999;
  transform:translateY(-100%);
  transition:transform .4s cubic-bezier(.4,0,.2,1);
  background:linear-gradient(90deg,rgba(180,15,15,.95),rgba(120,0,0,.95));
  backdrop-filter:blur(12px);
  border-bottom:1px solid rgba(239,68,68,.4);
  padding:.55rem 3%;
  display:flex;align-items:center;justify-content:space-between;gap:1rem;
}
#attackBar.show{transform:translateY(0);}
.atk-left{display:flex;align-items:center;gap:.8rem;}
.atk-pulse{width:10px;height:10px;border-radius:50%;background:#f87171;
  box-shadow:0 0 10px #ef4444;animation:blk .5s infinite alternate;flex-shrink:0;}
.atk-label{font-size:.82rem;font-weight:700;color:#fecaca;letter-spacing:.03em;}
.atk-desc{font-size:.75rem;color:rgba(252,165,165,.7);margin-top:.1rem;}
.atk-stats{display:flex;gap:1.5rem;}
.atk-stat{text-align:center;}
.atk-stat-v{font-size:1.1rem;font-weight:700;color:#f87171;line-height:1;}
.atk-stat-l{font-size:.62rem;color:rgba(252,165,165,.6);margin-top:.15rem;text-transform:uppercase;}
.atk-progress{flex:1;max-width:200px;}
.atk-progress-bar{height:4px;background:rgba(255,255,255,.1);border-radius:2px;overflow:hidden;}
.atk-progress-fill{height:100%;background:linear-gradient(90deg,#ef4444,#f97316);
  border-radius:2px;transition:width .5s;}
.atk-progress-label{font-size:.62rem;color:rgba(252,165,165,.6);margin-top:.25rem;}
.atk-shield{font-size:1.1rem;}

/* MITIGATION FLASH */
#mitBar{
  position:fixed;top:0;left:0;right:0;z-index:999;
  transform:translateY(-100%);transition:transform .4s cubic-bezier(.4,0,.2,1);
  background:linear-gradient(90deg,rgba(6,100,60,.95),rgba(4,80,60,.95));
  border-bottom:1px solid rgba(16,185,129,.4);
  padding:.6rem 3%;display:flex;align-items:center;justify-content:space-between;
}
#mitBar.show{transform:translateY(0);}
.mit-msg{color:#6ee7b7;font-weight:700;font-size:.88rem;}
.mit-sub{color:rgba(110,231,183,.6);font-size:.75rem;margin-top:.1rem;}

.ov-note{margin-top:1.5rem;color:#475569;font-size:.8rem;}

/* TOAST */
#toast{position:fixed;bottom:2rem;right:2rem;background:var(--acc);color:#fff;
  padding:.7rem 1.4rem;border-radius:10px;font-weight:600;font-size:.85rem;
  transform:translateY(80px);transition:transform .4s;z-index:800;}
#toast.show{transform:translateY(0);}
</style>
</head>
<body id="bd">

<!-- Attack Warning Bar (non-blocking) -->
<div id="attackBar">
  <div class="atk-left">
    <div class="atk-pulse"></div>
    <div>
      <div class="atk-label">⚠ DDoS ATTACK IN PROGRESS — ML Firewall Active</div>
      <div class="atk-desc">Store remains accessible to legitimate users. Attacker IPs are being blocked in real-time.</div>
    </div>
  </div>
  <div class="atk-stats">
    <div class="atk-stat"><div class="atk-stat-v" id="atkRate">0</div><div class="atk-stat-l">Pkts/sec</div></div>
    <div class="atk-stat"><div class="atk-stat-v" id="atkBlocked">0</div><div class="atk-stat-l">IPs Blocked</div></div>
    <div class="atk-stat"><div class="atk-stat-v" id="atkTotal">0</div><div class="atk-stat-l">Total Pkts</div></div>
  </div>
  <div class="atk-progress">
    <div class="atk-progress-bar"><div class="atk-progress-fill" id="atkProgress" style="width:0%"></div></div>
    <div class="atk-progress-label">🛡️ Mitigating… <span id="atkPct">0</span>% IPs blocked</div>
  </div>
  <div class="atk-shield">🔒</div>
</div>

<!-- Mitigation complete bar -->
<div id="mitBar">
  <div><div class="mit-msg">✅ Attack Wave Mitigated — Server Protected</div><div class="mit-sub" id="mitSub">ML Firewall blocked all attacker IPs.</div></div>
  <div style="color:#6ee7b7;font-size:1.5rem;">🛡️</div>
</div>

<!-- Toast -->
<div id="toast"></div>

<!-- NAV -->
<nav>
  <div class="logo">Aurora.</div>
  <div class="nav-center">
    <a onclick="goto('home')" id="nh" class="active">Home</a>
    <a onclick="goto('shop')" id="ns">Shop</a>
    <a onclick="goto('cart')" id="nc">Cart</a>
    <a onclick="goto('monitor')" id="nm">🛡 Security Monitor</a>
  </div>
  <div class="nav-right">
    <button class="cart-btn" onclick="goto('cart')">🛒 Cart <span class="cart-count" id="cartCount">0</span></button>
    <div class="pill ok" id="pill"><div class="dot" id="dot"></div><span id="pillTxt">Online</span></div>
  </div>
</nav>

<!-- PAGE: HOME -->
<div class="page active" id="pageHome">
  <div class="hero">
    <h1>Next-Gen Tech,<br>Delivered Fast.</h1>
    <p>Premium gadgets for the modern professional. Free shipping on orders over $50.</p>
    <div class="hero-cta">
      <button class="btn-pri" onclick="goto('shop')">Browse Collection →</button>
      <button class="btn-sec" onclick="goto('monitor')">🛡 View Security Monitor</button>
    </div>
  </div>
  <div class="stats" id="statsBar">
    <div class="sc safe" id="scStatus"><div class="lbl">Server Status</div><div class="val" id="scSv">Online</div><div class="sub">All systems operational</div></div>
    <div class="sc" id="scRate"><div class="lbl">Packet Rate</div><div class="val" id="scRv">0<small style="font-size:.75rem;color:#64748b">/s</small></div><div class="sub">live network rate</div></div>
    <div class="sc" id="scBlk"><div class="lbl">IPs Blocked</div><div class="val" id="scBv">0</div><div class="sub">by ML Firewall</div></div>
    <div class="sc" id="scTot"><div class="lbl">Total Packets</div><div class="val" id="scTv">0</div><div class="sub">received this session</div></div>
  </div>
  <!-- Featured Products -->
  <div style="padding:0 3% 3rem">
    <div style="font-size:1.3rem;font-weight:700;margin-bottom:1.2rem;">⭐ Featured Products</div>
    <div class="product-grid" id="featuredGrid"></div>
  </div>
</div>

<!-- PAGE: SHOP -->
<div class="page" id="pageShop">
  <div class="shop-layout">
    <div class="sidebar">
      <h3>Categories</h3>
      <button class="cat-btn active" id="catAll" onclick="filterCat('all',this)">All Products</button>
      <button class="cat-btn" id="catAudio" onclick="filterCat('Audio',this)">🎧 Audio</button>
      <button class="cat-btn" id="catWear" onclick="filterCat('Wearables',this)">⌚ Wearables</button>
      <button class="cat-btn" id="catPhone" onclick="filterCat('Phones',this)">📱 Phones</button>
      <button class="cat-btn" id="catLaptop" onclick="filterCat('Laptops',this)">💻 Laptops</button>
      <button class="cat-btn" id="catAccs" onclick="filterCat('Accessories',this)">🖱 Accessories</button>
      <button class="cat-btn" id="catCam" onclick="filterCat('Cameras',this)">📷 Cameras</button>
      <div class="price-filter">
        <h3 style="margin-bottom:.7rem;">Max Price</h3>
        <input type="range" min="50" max="2000" value="2000" id="priceSlider" oninput="filterPrice(this.value)">
        <div class="price-range-label">Up to $<span id="priceLabel">2000</span></div>
      </div>
    </div>
    <div>
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:1rem;">
        <div style="color:var(--mt);font-size:.85rem;" id="resultCount">Showing all products</div>
        <select id="sortSel" onchange="sortProducts()" style="background:var(--s);border:1px solid var(--b);color:var(--tx);padding:.4rem .7rem;border-radius:8px;font-family:inherit;font-size:.83rem;">
          <option value="default">Sort: Default</option>
          <option value="price-asc">Price: Low to High</option>
          <option value="price-desc">Price: High to Low</option>
          <option value="name">Name A-Z</option>
        </select>
      </div>
      <div class="product-grid" id="shopGrid"></div>
    </div>
  </div>
</div>

<!-- PAGE: PRODUCT DETAIL -->
<div class="page" id="pageDetail">
  <button class="pd-back" id="backBtn" onclick="goto('shop')">← Back to Shop</button>
  <div class="pd-layout" id="pdLayout"></div>
</div>

<!-- PAGE: CART -->
<div class="page" id="pageCart">
  <div class="cart-page">
    <h1>🛒 Your Cart</h1>
    <div id="cartContent"></div>
  </div>
</div>

<!-- PAGE: SECURITY MONITOR -->
<div class="page" id="pageMonitor">
  <div class="monitor-page">
    <h1>🛡 Live Security Monitor</h1>
    <div class="monitor-grid">
      <div>
        <div class="chart-panel">
          <div class="panel-lbl">📡 Network Traffic — Packets / Second (last 30s)</div>
          <canvas id="trafficChart" height="200"></canvas>
        </div>
        <div class="blocked-list" style="margin-top:1.2rem;">
          <div class="panel-lbl">🚫 Recently Blocked IPs (<span id="blCount">0</span> total)</div>
          <div id="blList" style="max-height:250px;overflow-y:auto;"></div>
        </div>
      </div>
      <div>
        <div class="log-box">
          <div class="panel-lbl">📋 Firewall Event Log</div>
          <div id="logList"></div>
        </div>
      </div>
    </div>
  </div>
</div>

<script>
// ─── PRODUCTS DATA ───────────────────────────────────────────────
const PRODUCTS = [
  {id:1,name:'Quantum Headphones Pro',cat:'Audio',icon:'🎧',price:299,rating:4.8,reviews:124,
   desc:'Active noise-canceling over-ear headphones with 40hr battery and spatial audio. Studio-quality sound in a premium titanium build.',
   specs:[['Driver','40mm dynamic'],['Battery','40 hrs ANC on'],['Connectivity','Bluetooth 5.3'],['Weight','245g']]},
  {id:2,name:'Nebula Smartwatch X',cat:'Wearables',icon:'⌚',price:199,rating:4.7,reviews:89,
   desc:'Ultra-thin titanium smartwatch with 3-week battery life, ECG, SpO₂, and always-on AMOLED display.',
   specs:[['Display','1.8" AMOLED AOD'],['Battery','21 days typical'],['Sensors','ECG, SpO₂, GPS'],['WR','5 ATM waterproof']]},
  {id:3,name:'Horizon Phone 15',cat:'Phones',icon:'📱',price:899,rating:4.9,reviews:312,
   desc:'Bezel-less glass display with AI-powered camera system, 200MP sensor, and Snapdragon 8 Gen 4 chipset.',
   specs:[['Display','6.8" 4K OLED 144Hz'],['Camera','200MP + 50MP periscope'],['RAM','16GB LPDDR5X'],['Storage','512GB UFS 4.0']]},
  {id:4,name:'Nova Laptop 14',cat:'Laptops',icon:'💻',price:1499,rating:4.8,reviews:67,
   desc:'Ultra-portable 14" laptop with Intel Core Ultra 9, 32GB RAM, and an exceptional 22hr battery life.',
   specs:[['CPU','Intel Core Ultra 9'],['RAM','32GB LPDDR5'],['Display','14" OLED 2.8K 120Hz'],['Battery','22 hrs mixed use']]},
  {id:5,name:'Aurora ANC Earbuds',cat:'Audio',icon:'🎵',price:149,rating:4.6,reviews:203,
   desc:'Compact true-wireless earbuds with ANC, transparency mode, and 32hr total playtime including case.',
   specs:[['Driver','10mm+6mm dual'],['ANC','-45dB hybrid'],['Battery','8hrs + 24hrs case'],['IP rating','IPX5']]},
  {id:6,name:'FitBand Ultra',cat:'Wearables',icon:'🏃',price:79,rating:4.4,reviews:441,
   desc:'Advanced fitness tracker with real-time GPS, 24/7 heart rate, sleep coaching, and 14-day battery.',
   specs:[['GPS','Multi-band GNSS'],['Battery','14 days fitness'],['Screen','1.4" AMOLED'],['Sports','100+ modes']]},
  {id:7,name:'Vortex Gaming Phone',cat:'Phones',icon:'🎮',price:749,rating:4.7,reviews:158,
   desc:'Purpose-built gaming smartphone with 165Hz display, shoulder triggers, 6,000mAh battery, and active cooling.',
   specs:[['Display','6.9" AMOLED 165Hz'],['Cooling','Active vapor chamber'],['Battery','6000mAh 67W'],['Triggers','Ultrasonic shoulder']]},
  {id:8,name:'ProBook Creator 16',cat:'Laptops',icon:'🖥',price:1999,rating:4.9,reviews:44,
   desc:'16-inch powerhouse for creators — RTX 4080, mini-LED ProMotion display, and professional-grade color accuracy.',
   specs:[['CPU','AMD Ryzen 9 9950X'],['GPU','RTX 4080 16GB'],['Display','16" mini-LED 4K 240Hz'],['RAM','64GB DDR5']]},
  {id:9,name:'MagClick Hub Pro',cat:'Accessories',icon:'🖱',price:59,rating:4.5,reviews:289,
   desc:'8-in-1 magnetic hub with 100W PD, 4K HDMI, 10Gbps USB-A, SD card reader, and compact fold-flat design.',
   specs:[['Ports','USB-C×2, USB-A×2, HDMI, SD, MicroSD, 3.5mm'],['PD Pass-through','100W'],['Data','10Gbps USB 3.2'],['Video','4K60 HDMI']]},
  {id:10,name:'StealthCam 4K',cat:'Cameras',icon:'📷',price:649,rating:4.8,reviews:92,
   desc:'Compact mirrorless camera with 45MP BSI-CMOS sensor, 4K120 video, in-body stabilisation, and weather sealing.',
   specs:[['Sensor','45MP BSI-CMOS'],['Video','4K120, 6K30'],['IBIS','8-stop stabilization'],['Sealing','IPX4']]},
  {id:11,name:'StreamKey 4K Pro',cat:'Accessories',icon:'🎙',price:119,rating:4.6,reviews:176,
   desc:'4K streaming key for content creators — hardware encoding, instant scene switching, and multi-platform support.',
   specs:[['Encoding','AV1, H.265 hardware'],['Output','4K60 stream'],['Latency','<2ms'],['Compat','OBS, Kick, YouTube']]},
  {id:12,name:'HoloLens Vision',cat:'Wearables',icon:'🥽',price:499,rating:4.3,reviews:38,
   desc:'Mixed-reality AR glasses with spatial computing, real-time translation, and 6hr active use battery.',
   specs:[['Display','MicroOLED, 50° FOV'],['CPU','Snapdragon AR2 Gen 3'],['Battery','6 hrs active'],['Weight','68g']]},
];

let cart = {};
let currentCat = 'all';
let maxPrice = 2000;
let detailId = null;
let prevStatus = 'healthy';
let bannerTimer = null;

// ─── NAVIGATION ──────────────────────────────────────────────────
function goto(page) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-center a').forEach(a => a.classList.remove('active'));
  const map = {home:'pageHome',shop:'pageShop',detail:'pageDetail',cart:'pageCart',monitor:'pageMonitor'};
  const nmap = {home:'nh',shop:'ns',detail:'ns',cart:'nc',monitor:'nm'};
  document.getElementById(map[page]).classList.add('active');
  const nEl = document.getElementById(nmap[page]);
  if (nEl) nEl.classList.add('active');
  if (page === 'shop') renderShop();
  if (page === 'home') renderFeatured();
  if (page === 'cart') renderCart();
  if (page === 'monitor') renderBlockedList();
  window.scrollTo(0, 0);
}

// ─── PRODUCT CARD ─────────────────────────────────────────────────
function makeCard(p) {
  return `<div class="pc" onclick="openDetail(${p.id})">
    <div class="pi">${p.icon}</div>
    <div class="pc-body">
      <div class="pc-cat">${p.cat}</div>
      <div class="pc-name">${p.name}</div>
      <div class="pc-desc">${p.desc.substring(0,70)}…</div>
      <div class="pc-footer">
        <div class="pc-price">$${p.price}</div>
        <button class="add-btn" onclick="event.stopPropagation();addCart(${p.id})">${cart[p.id]?'✓ In Cart':'Add'}</button>
      </div>
    </div>
  </div>`;
}

function renderFeatured() {
  const featured = [1,3,4,10,5,6];
  document.getElementById('featuredGrid').innerHTML = featured.map(id => makeCard(PRODUCTS.find(p=>p.id===id))).join('');
}
function renderShop() {
  let list = PRODUCTS.filter(p => (currentCat==='all' || p.cat===currentCat) && p.price<=maxPrice);
  const sort = document.getElementById('sortSel').value;
  if (sort==='price-asc') list.sort((a,b)=>a.price-b.price);
  else if (sort==='price-desc') list.sort((a,b)=>b.price-a.price);
  else if (sort==='name') list.sort((a,b)=>a.name.localeCompare(b.name));
  document.getElementById('shopGrid').innerHTML = list.map(makeCard).join('');
  document.getElementById('resultCount').textContent = `Showing ${list.length} of ${PRODUCTS.length} products`;
}

function filterCat(cat, el) {
  currentCat = cat;
  document.querySelectorAll('.cat-btn').forEach(b=>b.classList.remove('active'));
  el.classList.add('active');
  renderShop();
}
function filterPrice(v) {
  maxPrice = +v;
  document.getElementById('priceLabel').textContent = v;
  renderShop();
}
function sortProducts() { renderShop(); }

// ─── PRODUCT DETAIL ───────────────────────────────────────────────
function openDetail(id) {
  detailId = id;
  const p = PRODUCTS.find(x=>x.id===id);
  const inCart = cart[id] || 0;
  document.getElementById('pdLayout').innerHTML = `
    <div class="pd-img">${p.icon}</div>
    <div class="pd-info">
      <div class="pd-badge">${p.cat}</div>
      <h1>${p.name}</h1>
      <div style="color:var(--y);margin:.3rem 0;">★★★★★ <small style="color:var(--mt)">${p.rating} (${p.reviews} reviews)</small></div>
      <div class="pd-price">$${p.price}</div>
      <p class="pd-desc">${p.desc}</p>
      <div class="pd-specs">
        ${p.specs.map(s=>`<div class="pd-spec"><span class="pd-spec-k">${s[0]}</span><span>${s[1]}</span></div>`).join('')}
      </div>
      <div class="qty-row">
        <button class="qty-btn" onclick="adjQty(${id},-1)">−</button>
        <div class="qty-val" id="qv${id}">${inCart||1}</div>
        <button class="qty-btn" onclick="adjQty(${id},1)">+</button>
      </div>
      <button class="add-to-cart-big" onclick="addCart(${id})">🛒 ${inCart?'Update Cart':'Add to Cart'}</button>
    </div>`;
  goto('detail');
}
function adjQty(id, d) {
  const el = document.getElementById('qv'+id);
  let v = Math.max(1, (+el.textContent)+d);
  el.textContent = v;
}

// ─── CART ─────────────────────────────────────────────────────────
function addCart(id) {
  const p = PRODUCTS.find(x=>x.id===id);
  const qEl = document.getElementById('qv'+id);
  const qty = qEl ? +qEl.textContent : 1;
  cart[id] = (cart[id]||0) + qty;
  updateCartCount();
  showToast(`✓ ${p.name} added to cart!`);
  renderShop();
  renderFeatured();
}
function removeCart(id) { delete cart[id]; renderCart(); updateCartCount(); }
function adjCartQty(id, d) {
  cart[id] = Math.max(1, (cart[id]||1)+d);
  renderCart(); updateCartCount();
}
function updateCartCount() {
  const total = Object.values(cart).reduce((a,b)=>a+b,0);
  document.getElementById('cartCount').textContent = total;
}
function renderCart() {
  const ids = Object.keys(cart);
  const el = document.getElementById('cartContent');
  if (!ids.length) {
    el.innerHTML = `<div class="cart-empty"><div class="ei">🛒</div><div style="font-size:1.1rem;font-weight:600;">Your cart is empty</div><div style="color:var(--mt);margin:.5rem 0 1.5rem;">Start shopping to add products.</div><button class="btn-pri" onclick="goto('shop')">Browse Products</button></div>`;
    return;
  }
  let sub = 0;
  const rows = ids.map(id => {
    const p = PRODUCTS.find(x=>x.id==id);
    const line = p.price * cart[id];
    sub += line;
    return `<tr>
      <td><div style="display:flex;align-items:center;gap:.8rem;"><div style="font-size:2rem">${p.icon}</div><div><div class="ci-name">${p.name}</div><div class="ci-cat">${p.cat}</div></div></div></td>
      <td>$${p.price}</td>
      <td><div class="cart-qty"><button onclick="adjCartQty(${id},-1)">−</button><span>${cart[id]}</span><button onclick="adjCartQty(${id},1)">+</button></div></td>
      <td>$${line}</td>
      <td><button class="rm-btn" onclick="removeCart(${id})">🗑</button></td>
    </tr>`;
  }).join('');
  const tax = (sub*0.08).toFixed(2);
  const total = (sub*1.08).toFixed(2);
  el.innerHTML = `<table class="cart-table"><thead><tr><th>Product</th><th>Price</th><th>Qty</th><th>Subtotal</th><th></th></tr></thead><tbody>${rows}</tbody></table>
  <div class="cart-summary">
    <div class="cs-row"><span>Subtotal</span><span>$${sub.toFixed(2)}</span></div>
    <div class="cs-row"><span>Shipping</span><span>Free</span></div>
    <div class="cs-row"><span>Tax (8%)</span><span>$${tax}</span></div>
    <div class="cs-total"><span>Total</span><span>$${total}</span></div>
    <button class="checkout-btn" onclick="showToast('🎉 Order placed! (Demo)')">Proceed to Checkout →</button>
  </div>`;
}

// ─── TOAST ────────────────────────────────────────────────────────
let toastTimer;
function showToast(msg) {
  const t = document.getElementById('toast');
  t.textContent = msg; t.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(()=>t.classList.remove('show'), 2800);
}

// ─── CHART ────────────────────────────────────────────────────────
const ctx = document.getElementById('trafficChart').getContext('2d');
const chartData = Array(30).fill(0);
const trafficChart = new Chart(ctx, {
  type:'line',
  data:{labels:Array(30).fill(''),datasets:[{label:'Packets/s',data:chartData,
    borderColor:'#3b82f6',backgroundColor:'rgba(59,130,246,.1)',borderWidth:2,fill:true,tension:.4,pointRadius:0}]},
  options:{animation:false,responsive:true,plugins:{legend:{display:false}},
    scales:{x:{display:false},y:{min:0,grid:{color:'rgba(255,255,255,.05)'},ticks:{color:'#64748b',font:{size:10}}}}}
});

// ─── LOG ──────────────────────────────────────────────────────────
function addLog(msg, cls) {
  const el = document.getElementById('logList');
  if (!el) return;
  const d = document.createElement('div');
  d.className = 'le ' + (cls||'');
  d.textContent = '['+new Date().toLocaleTimeString()+'] '+msg;
  el.prepend(d);
  while(el.children.length > 80) el.removeChild(el.lastChild);
}

function renderBlockedList() {
  fetch('/api/live_status').then(r=>r.json()).then(d=>{
    document.getElementById('blCount').textContent = d.total_blocked;
    const el = document.getElementById('blList');
    const ips = Object.entries(d.blocked_ips||{}).reverse().slice(0,20);
    el.innerHTML = ips.length ? ips.map(([ip,info])=>`
      <div class="bl-item">
        <span class="bl-ip">${ip}</span>
        <span class="bl-time">${info.timestamp||''}</span>
      </div>`).join('') : '<div style="color:var(--mt);font-size:.8rem;text-align:center;padding:1rem;">No IPs blocked yet.</div>';
  }).catch(()=>{});
}

function fmt(n){ return n>=1000000?(n/1000000).toFixed(1)+'M':n>=1000?(n/1000).toFixed(1)+'k':n; }

// ─── MAIN POLL ────────────────────────────────────────────────────
async function poll() {
  try {
    const r = await fetch('/api/live_status');
    const d = await r.json();
    const {status, packets_per_sec:rate, total_blocked:blocked, total_packets_received:total, newly_blocked:newIps=[]} = d;

    // Chart
    chartData.push(rate); chartData.shift();
    const ds = trafficChart.data.datasets[0];
    ds.borderColor = status==='attacking'?'#ef4444':status==='mitigated'?'#10b981':'#3b82f6';
    ds.backgroundColor = status==='attacking'?'rgba(239,68,68,.1)':status==='mitigated'?'rgba(16,185,129,.08)':'rgba(59,130,246,.1)';
    trafficChart.update('none');

    // Stats bar
    document.getElementById('scRv').innerHTML = fmt(rate)+'<small style="font-size:.75rem;color:#64748b">/s</small>';
    document.getElementById('scBv').textContent = blocked;
    document.getElementById('scTv').textContent = fmt(total);

    // Overlay counters
    document.getElementById('ovRate').textContent = fmt(rate);
    document.getElementById('ovBlocked').textContent = blocked;
    document.getElementById('ovTotal').textContent = fmt(total);

    // Blocked IPs counter on monitor
    const blC = document.getElementById('blCount');
    if (blC) blC.textContent = blocked;

    // New IPs — log them
    newIps.forEach(ip => {
      addLog('🚫 BLOCKED: '+ip+' — ML-based DDoS Detection', 'blk');
      const el = document.getElementById('blList');
      if (el) {
        const row = document.createElement('div');
        row.className = 'bl-item';
        row.innerHTML = `<span class="bl-ip">${ip}</span><span class="bl-time">${new Date().toLocaleTimeString()}</span>`;
        el.prepend(row);
      }
    });

    // Attack Warning Bar
    const atkBar = document.getElementById('attackBar');
    const mitBar = document.getElementById('mitBar');
    const pill = document.getElementById('pill');
    const pillTxt = document.getElementById('pillTxt');
    const body = document.getElementById('bd');

    // Always update attack bar counters
    document.getElementById('atkRate').textContent    = fmt(rate);
    document.getElementById('atkBlocked').textContent = blocked;
    document.getElementById('atkTotal').textContent   = fmt(total);
    // Progress = % of current wave's 50 IPs blocked (estimate)
    const waveSize = 50;
    const wavePct = Math.min(100, Math.round((blocked % waveSize || (blocked > 0 ? waveSize : 0)) / waveSize * 100));
    document.getElementById('atkProgress').style.width = wavePct + '%';
    document.getElementById('atkPct').textContent = wavePct;

    if (status === 'attacking') {
      body.className = 'att';
      atkBar.classList.add('show');
      mitBar.classList.remove('show');
      pill.className = 'pill bad'; pillTxt.textContent = '⚠ Under Attack';
      document.getElementById('scSv').textContent = 'Under Attack (Mitigating)';
      document.getElementById('scStatus').className = 'sc danger';
      document.getElementById('scRate').className = 'sc danger';
      if (prevStatus !== 'attacking') addLog('🔴 DDoS ATTACK STARTED — ML Firewall is blocking IPs, store stays open for legit users', 'det');

    } else if (status === 'mitigated') {
      body.className = 'mit';
      atkBar.classList.remove('show');
      mitBar.classList.add('show');
      pill.className = 'pill mit'; pillTxt.textContent = '✅ Mitigated';
      document.getElementById('scSv').textContent = 'Protected';
      document.getElementById('scStatus').className = 'sc safe';
      document.getElementById('scRate').className = 'sc';
      if (prevStatus === 'attacking') {
        addLog('✅ WAVE MITIGATED — All ' + blocked + ' attacker IPs blocked. Awaiting next wave.', 'mit');
        document.getElementById('mitSub').textContent = 'Blocked ' + blocked + ' attacker IPs this session. Next wave may follow.';
      }
      // Auto-hide mitigation bar after 6s
      setTimeout(()=>mitBar.classList.remove('show'), 6000);

    } else {
      body.className = '';
      atkBar.classList.remove('show');
      mitBar.classList.remove('show');
      pill.className = 'pill ok'; pillTxt.textContent = 'Online';
      document.getElementById('scSv').textContent = 'Online';
      document.getElementById('scStatus').className = 'sc safe';
      document.getElementById('scRate').className = 'sc';
      if (prevStatus === 'attacking') addLog('🟢 Server fully back to normal.', 'norm');
    }

    prevStatus = status;
  } catch(e) {}
}

function showBanner(msg) {
  const b = document.getElementById('banner');
  document.getElementById('bannerMsg').textContent = msg;
  b.classList.add('show');
  clearTimeout(bannerTimer);
  bannerTimer = setTimeout(()=>b.classList.remove('show'), 7000);
}

// Init
renderFeatured();
setInterval(poll, 1000);
poll();
</script>
</body>
</html>"""

@app.route('/')
def home():
    return render_template_string(HTML)

@app.route('/api/live_status')
def live_status():
    sync_blocked()
    with lock:
        newly = list(state.get("_new_ips", set()))
        state["_new_ips"] = set()
        return jsonify({
            "status": state["status"],
            "packets_per_sec": state["packets_per_sec"],
            "total_packets_received": state["total_packets_received"],
            "total_blocked": state["total_blocked"],
            "blocked_ips": state["blocked_ips"],
            "rate_history": list(state["rate_history"]),
            "newly_blocked": newly,
        })

@app.route('/api/report_traffic', methods=['POST'])
def report_traffic():
    try:
        d = request.get_json(force=True) or {}
        rate    = int(d.get("rate", 0))
        new_ips = d.get("blocked_ips", [])
        total   = int(d.get("total_packets", 0))
        with lock:
            state["packets_per_sec"] = rate
            if total: state["total_packets_received"] = total
            else:     state["total_packets_received"] += rate
            # ANY incoming traffic above threshold = attacking (even after mitigated)
            if rate > 30:
                state["under_attack"] = True
                state["status"] = "attacking"
            elif rate == 0 and state["status"] == "attacking":
                # Explicit zero signal from generator = wave ended, start recovery
                pass  # bg_sync will handle the transition
            if "_new_ips" not in state: state["_new_ips"] = set()
            for ip in new_ips:
                if ip not in state["blocked_ips"]:
                    state["_new_ips"].add(ip)
                    state["blocked_ips"][ip] = {
                        "reason": "ML-Based DDoS Detection",
                        "timestamp": datetime.now().strftime("%H:%M:%S"),
                        "status": "Blocked"
                    }
            state["total_blocked"] = len(state["blocked_ips"])
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400

@app.route('/api/reset', methods=['POST'])
def reset():
    with lock:
        state.update({"under_attack":False,"packets_per_sec":0,"total_packets_received":0,
                      "total_blocked":0,"blocked_ips":{},"status":"healthy",
                      "_new_ips":set(),"_prev_blocked":set()})
        state["rate_history"].clear()
    try:
        with open(BLOCKED_IPS_FILE,'w') as f: json.dump({},f)
    except: pass
    return jsonify({"ok": True})

if __name__ == '__main__':
    import socket
    lan_ip = socket.gethostbyname(socket.gethostname())
    print(f"🚀 Aurora E-Commerce running → http://localhost:8080")
    print(f"🌐 LAN Access (share this with your friend) → http://{lan_ip}:8080")
    app.run(debug=False, host='0.0.0.0', port=8080, threaded=True)
