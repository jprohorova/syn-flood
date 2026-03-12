import time, math, argparse, signal
from collections import Counter, deque
from dataclasses import dataclass
from scapy.all import sniff, TCP, IP

stop = False
alert_until = 0.0
cooldown_until = 0.0

def on_sigint(sig, frame):
    global stop
    stop = True

@dataclass
class Cfg:
    window: float = 1.0
    port: int | None = None
    syn_thresh: int = 100
    ratio_thresh: float = 5.0
    half_open_thresh: float = 0.80
    iface: str | None = None
    alert_hold: float = 3.0
    cooldown: float = 1.0

syn_t = deque()
ack_t = deque()
synack_t = deque()
src_ips = deque()

def prune(q, window):
    cutoff = time.time() - window
    while q and q[0] < cutoff:
        q.popleft()

def prune_src(q, window):
    cutoff = time.time() - window
    while q and q[0][0] < cutoff:
        q.popleft()

def entropy(counts):
    total = sum(counts.values())
    if total == 0:
        return 0.0
    h = 0.0
    for c in counts.values():
        p = c / total
        h -= p * math.log2(p)
    return h

def handle(pkt, cfg: Cfg):
    if IP not in pkt or TCP not in pkt:
        return
    ip = pkt[IP]
    tcp = pkt[TCP]

    if cfg.port is not None and tcp.dport != cfg.port and tcp.sport != cfg.port:
        return

    ts = time.time()
    flags = tcp.flags

    if flags & 0x02 and not (flags & 0x10):
        syn_t.append(ts)
        src_ips.append((ts, ip.src))

    if flags & 0x10:
        ack_t.append(ts)

    if (flags & 0x02) and (flags & 0x10):
        synack_t.append(ts)

def snapshot(cfg: Cfg):
    prune(syn_t, cfg.window)
    prune(ack_t, cfg.window)
    prune(synack_t, cfg.window)
    prune_src(src_ips, cfg.window)

    syn = len(syn_t)
    ack = len(ack_t)
    synack = len(synack_t)

    ratio = syn / max(1, synack)
    half_open = max(0.0, min(1.0, (syn - synack) / max(1, syn)))

    counts = Counter(ip for _, ip in src_ips)
    ent = entropy(counts)

    alert = (
        syn >= cfg.syn_thresh and
        ratio >= cfg.ratio_thresh and
        half_open >= cfg.half_open_thresh
    )

    status = "ALERT" if alert else "NORMAL"
    print(
        f"[{time.strftime('%H:%M:%S')}] {status} | "
        f"SYN {syn:>5}/s  SYN-ACK {synack:>5}/s  ACK {ack:>5}/s  "
        f"ratio(SYN/SYN-ACK) {ratio:>6.1f}  "
        f"srcs {len(counts):>4}  H-open {half_open*100:>3.0f}%  ent {ent:>4.2f}"
    )

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iface", default=None, help="e.g. lo0 or en0")
    ap.add_argument("--port", type=int, default=None)
    ap.add_argument("--window", type=float, default=1.0)
    ap.add_argument("--syn-thresh", type=int, default=100)
    ap.add_argument("--ratio", type=float, default=5.0)
    ap.add_argument("--half-open", type=float, default=0.80)
    args = ap.parse_args()

    cfg = Cfg(
        window=args.window,
        port=args.port,
        syn_thresh=args.syn_thresh,
        ratio_thresh=args.ratio,
        half_open_thresh=args.half_open,
        iface=args.iface
    )

    signal.signal(signal.SIGINT, on_sigint)

    # BPF filter for performance
    flt = "tcp"
    if cfg.port is not None:
        flt = f"tcp and port {cfg.port}"

    print(f"[+] sniff on iface={cfg.iface or 'default'} filter='{flt}' (Ctrl+C to stop)")

    last = time.time()
    while not stop:
        # sniff in short bursts
        sniff(iface=cfg.iface, filter=flt, prn=lambda p: handle(p, cfg), store=False, timeout=0.25)
        if time.time() - last >= cfg.window:
            snapshot(cfg)
            last = time.time()

if __name__ == "__main__":
    main()