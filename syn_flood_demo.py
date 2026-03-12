#!/usr/bin/env python3

import argparse
import math
import random
import threading
import time
from collections import Counter, deque
from dataclasses import dataclass, field
from typing import Deque, Dict, List, Tuple

# TCP flags
FLAG_SYN = 0x02
FLAG_ACK = 0x10

@dataclass  
class TCPPacket: 
    src_ip: str # source IP address
    dst_ip: str # destination IP address
    src_port: int # source TCP port
    dst_port: int # destination TCP port
    flags: int # TCP control flags as a bitmask (SYN, ACK) defining the segment role in the handshake
    timestamp: float = field(default_factory=time.time) # packet creation time used for sliding-window rate analysis

    @property 
    def is_syn(self) -> bool:  # true if packet is an initial SYN
        return (self.flags & FLAG_SYN) and not (self.flags & FLAG_ACK)  # SYN set and ACK not set => connection request

    @property 
    def is_syn_ack(self) -> bool:  # True if packet is a SYN-ACK (server reply, second step of the handshake)
        return (self.flags & FLAG_SYN) and (self.flags & FLAG_ACK)  # SYN and ACK set => acknowledgment + synchronization

    @property
    def is_ack(self) -> bool: # true if packet carries ACK
        return bool(self.flags & FLAG_ACK) # ACK bit set => acknowledges receipt / progresses connection state


def make_legit(port: int) -> Tuple[TCPPacket, TCPPacket, TCPPacket]:
    client = f"192.168.1.{random.randint(2, 254)}"
    p = random.randint(40000, 60000)
    syn = TCPPacket(client, "127.0.0.1", p, port, FLAG_SYN)
    syn_ack = TCPPacket("127.0.0.1", client, port, p, FLAG_SYN | FLAG_ACK)
    ack = TCPPacket(client, "127.0.0.1", p, port, FLAG_ACK)
    return syn, syn_ack, ack


def make_flood_syn(port: int) -> TCPPacket:
    src = f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
    return TCPPacket(src, "127.0.0.1", random.randint(1024, 65535), port, FLAG_SYN)

def make_syn_ack_reply(src_ip: str, port: int) -> TCPPacket:
    return TCPPacket("127.0.0.1", src_ip, port, random.randint(1024, 65535), FLAG_SYN | FLAG_ACK)

# sliding window counters
class SlidingCounter:
    def __init__(self, window: float):
        self.window = window
        self.q: Deque[float] = deque()

    def add(self, ts: float) -> None:
        self.q.append(ts)

    def count(self, now: float) -> int:
        cutoff = now - self.window
        while self.q and self.q[0] < cutoff:
            self.q.popleft()
        return len(self.q)


@dataclass
class DetectorConfig:
    window: float = 1.0
    syn_thresh: int = 100
    ratio_thresh: float = 5.0 # SYN / SYN-ACK
    half_open_thresh: float = 0.80 # (SYN - SYN-ACK)/SYN


class FloodDetector:
    def __init__(self, cfg: DetectorConfig):
        self.cfg = cfg
        self.syn = SlidingCounter(cfg.window)
        self.ack = SlidingCounter(cfg.window)
        self.synack = SlidingCounter(cfg.window)

        self.src_q: Deque[Tuple[float, str]] = deque()
        self.src_counts: Dict[str, int] = {}

        self.total_pkts = 0
        self.total_syn = 0
        self.total_ack = 0
        self.alerts: List[dict] = []

        self._in_alert = False
        self._lock = threading.Lock()

    def process(self, pkt: TCPPacket) -> Tuple[bool, dict]:
        now = pkt.timestamp
        with self._lock:
            self.total_pkts += 1

            # src tracking for unique count + entropy
            self.src_q.append((now, pkt.src_ip))
            self.src_counts[pkt.src_ip] = self.src_counts.get(pkt.src_ip, 0) + 1
            cutoff = now - self.cfg.window
            while self.src_q and self.src_q[0][0] < cutoff:
                _, old = self.src_q.popleft()
                self.src_counts[old] -= 1
                if self.src_counts[old] <= 0:
                    del self.src_counts[old]

            if pkt.is_syn:
                self.syn.add(now)
                self.total_syn += 1
            if pkt.is_syn_ack:
                self.synack.add(now)
            if pkt.is_ack:
                self.ack.add(now)
                self.total_ack += 1

            snap = self.snapshot(now)
            is_alert = self._check_alert(snap, now)
            return is_alert, snap

    def snapshot(self, now: float | None = None) -> dict:
        if now is None:
            now = time.time()

        syn = self.syn.count(now)
        ack = self.ack.count(now)
        synack = self.synack.count(now)

        ratio = syn / max(1, synack)
        half_open = (syn - synack) / max(1, syn)
        half_open = max(0.0, min(1.0, half_open))  # avoid negative / >100%

        unique_src = len(self.src_counts)
        ent = self._entropy()

        return {
            "syn": syn,
            "ack": ack,
            "synack": synack,
            "ratio": ratio,
            "half_open": half_open,
            "unique_src": unique_src,
            "entropy": ent,
        }

    def _entropy(self) -> float:
        total = sum(self.src_counts.values())
        if total <= 0:
            return 0.0
        h = 0.0
        for c in self.src_counts.values():
            p = c / total
            h -= p * math.log2(p)
        return h

    def _check_alert(self, snap: dict, now: float) -> bool:
        triggered = (
            snap["syn"] >= self.cfg.syn_thresh and
            snap["ratio"] >= self.cfg.ratio_thresh and
            snap["half_open"] >= self.cfg.half_open_thresh
        )

        if triggered and not self._in_alert:
            self._in_alert = True
            self.alerts.append({"time": now, "snap": snap})
        if not triggered:
            self._in_alert = False

        return triggered


# traffic
def legit_worker(det: FloodDetector, port: int, rate: int, stop: threading.Event) -> None:
    delay = 1.0 / max(1, rate)
    while not stop.is_set():
        syn, syn_ack, ack = make_legit(port)
        det.process(syn)
        time.sleep(0.001)
        det.process(syn_ack)
        time.sleep(0.001)
        det.process(ack)
        time.sleep(delay)


def flood_worker(det: FloodDetector, port: int, rate: int, stop: threading.Event, synack_prob: float) -> None:
    delay = 1.0 / max(1, rate)
    while not stop.is_set():
        syn = make_flood_syn(port)
        det.process(syn)

        # server sometimes answers with SYN-ACK, but attacker never completes with final ACK
        if random.random() < synack_prob:
            det.process(make_syn_ack_reply(syn.src_ip, port))

        time.sleep(delay)


# scenario
@dataclass
class Phase:
    name: str
    duration: float
    flood_rate: int # SYN/s total
    legit_rate: int # handshakes/s
    synack_prob: float # probability server replies with SYN-ACK for flood


SCENARIO = [
    Phase("Baseline", 5, 0, 5, 1.00),
    Phase("Ramp-up", 4, 80, 5, 0.10),
    Phase("Attack", 8, 500, 2, 0.05),
    Phase("Peak", 6, 900, 1, 0.02),
    Phase("Recovery", 5, 0, 5, 1.00),
]


def run(args) -> None:
    cfg = DetectorConfig(
        window=args.window,
        syn_thresh=args.syn_thresh,
        ratio_thresh=args.ratio,
        half_open_thresh=args.half_open,
    )
    det = FloodDetector(cfg)
    port = args.port

    print("time     phase      SYN/s  SYN-ACK  ratio   H-open  srcs  status")
    print("-------- ---------- ------ ------- ------ ------- ----- --------")

    last_alert = False

    for ph in SCENARIO:
        flood_stop = threading.Event()
        legit_stop = threading.Event()

        legit_threads: List[threading.Thread] = []
        flood_threads: List[threading.Thread] = []

        if ph.legit_rate > 0:
            t = threading.Thread(target=legit_worker, args=(det, port, ph.legit_rate, legit_stop), daemon=True)
            t.start()
            legit_threads.append(t)

        if ph.flood_rate > 0:
            n = max(1, min(args.threads, 8))
            per = max(1, ph.flood_rate // n)
            for _ in range(n):
                t = threading.Thread(
                    target=flood_worker,
                    args=(det, port, per, flood_stop, ph.synack_prob),
                    daemon=True,
                )
                t.start()
                flood_threads.append(t)

        end = time.time() + ph.duration
        while time.time() < end:
            snap = det.snapshot()
            is_alert = (
                snap["syn"] >= cfg.syn_thresh and
                snap["ratio"] >= cfg.ratio_thresh and
                snap["half_open"] >= cfg.half_open_thresh
            )

            status = "ALERT" if is_alert else ("ELEV" if snap["syn"] > 20 else "OK")
            ts = time.strftime("%H:%M:%S")

            # small one-line alert edge (minimal, no big boxes)
            if is_alert and not last_alert:
                print(f"--- alert start: syn={snap['syn']}/s ratio={snap['ratio']:.1f} hopen={snap['half_open']*100:.0f}%")
            last_alert = is_alert

            print(
                f"{ts:8} {ph.name:10} "
                f"{snap['syn']:6} {snap['synack']:7} "
                f"{snap['ratio']:6.1f} {snap['half_open']*100:6.0f}% "
                f"{snap['unique_src']:5} {status:8}"
            )
            time.sleep(1.0)

        flood_stop.set()
        legit_stop.set()
        time.sleep(0.2)

    print("\nsummary")
    print(f"pkts={det.total_pkts:,}  syn={det.total_syn:,}  ack={det.total_ack:,}  alerts={len(det.alerts)}")
    if det.alerts:
        first = det.alerts[0]["snap"]
        print(f"first alert: syn={first['syn']}/s ratio={first['ratio']:.1f} hopen={first['half_open']*100:.0f}% srcs={first['unique_src']}")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=80)
    ap.add_argument("--threads", type=int, default=4)
    ap.add_argument("--window", type=float, default=1.0)
    ap.add_argument("--syn-thresh", type=int, default=100)
    ap.add_argument("--ratio", type=float, default=5.0)
    ap.add_argument("--half-open", type=float, default=0.80)
    args = ap.parse_args()
    run(args)


if __name__ == "__main__":
    main()