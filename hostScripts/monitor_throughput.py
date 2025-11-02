#!/usr/bin/env python3
"""
monitor_throughput.py

Improved version with:
- aligned dashboard columns
- more accurate throughput calculation using multiple samples (linear regression over recent samples)
- instantaneous (last-2-samples), regression-based throughput (more robust), and EWMA
- keeps big-endian interpretation for counters and timestamps
- CLI mode control: run as sender, receiver, or both (default both)

Run examples:
  sudo python3 monitor_throughput.py --mode both --send-if enp6s0f0 --recv-if enp6s0f1 --file instruc.txt --log monitor_log.csv
  sudo python3 monitor_throughput.py --mode send  --send-if enp6s0f0 --file instruc.txt
  sudo python3 monitor_throughput.py --mode recv  --recv-if enp6s0f1 --log monitor_log.csv

"""

import argparse
import threading
import time
import struct
import os
import sys
import csv
from collections import deque
from typing import Dict, Optional
from scapy.all import Ether, IP, Raw, sendp, sniff, conf

# Defaults
DEFAULT_SEND_IF = "enp6s0f0"
DEFAULT_RECV_IF = "enp6s0f1"
IP_SRC = "172.168.0.1"
IP_DST = "172.168.0.2"
ETH_TYPE_MON = 0x1234
ETH_HDR_LEN = 14
MONITOR_INST_LEN = 10
MONITOR_H_LEN = 50  # according to spec

# Throughput EWMA alpha default
DEFAULT_EWMA_ALPHA = 0.3
# Number of recent samples to keep for regression
SAMPLES_KEEP = 8


# Parse input flows
def parse_flows_file(path: str):
    flows = []
    with open(path, "r") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = [p.strip() for p in line.split(",")]
            kv = {}
            for p in parts:
                if "=" not in p:
                    continue
                k, v = p.split("=", 1)
                kv[k.strip()] = v.strip()
            try:
                flow = int(kv.get("flow"))
                port = int(kv.get("port"))
                period = float(kv.get("period"))
            except Exception as e:
                raise ValueError(f"Invalid line '{line}': {e}")
            flows.append({"flow": flow, "port": port, "period": period})
    return flows


# Build monitor_inst header (big-endian)
def build_monitor_inst(index_flow: int, index_port: int, small_port: int) -> bytes:
    small_port = small_port & 0x1FF
    packed = struct.pack("!IIH", index_flow & 0xFFFFFFFF, index_port & 0xFFFFFFFF, (small_port << 7) & 0xFFFF)
    return packed


# Sender thread
def flow_sender_thread(iface: str, flow_cfg: Dict, stop_event: threading.Event):
    index_flow = int(flow_cfg["flow"]) & 0xFFFFFFFF
    index_port = int(flow_cfg["port"]) & 0xFFFFFFFF
    period = float(flow_cfg["period"])
    small_port = index_port & 0x1FF
    mon_inst = build_monitor_inst(index_flow, index_port, small_port)

    target_total = 100
    target_ip_bytes_len = target_total - ETH_HDR_LEN - MONITOR_INST_LEN
    ip_header_len = 20
    ip_payload_len = target_ip_bytes_len - ip_header_len
    if ip_payload_len < 0:
        raise ValueError("Target too small")

    fake_payload = (b"MON" * ((ip_payload_len // 3) + 1))[:ip_payload_len]
    ip_pkt = IP(src=IP_SRC, dst=IP_DST) / Raw(fake_payload)
    ip_bytes = bytes(ip_pkt)
    actual_len = ETH_HDR_LEN + len(mon_inst) + len(ip_bytes)
    if actual_len != target_total:
        if actual_len < target_total:
            pad = target_total - actual_len
            ip_bytes = bytes(IP(src=IP_SRC, dst=IP_DST) / Raw(fake_payload + b"" * pad))
        else:
            raise RuntimeError("packet too long")

    frame_payload = mon_inst + ip_bytes
    frame = Ether(type=ETH_TYPE_MON) / Raw(frame_payload)

    # Try to set a destination MAC to avoid Scapy printing ARP/broadcast warnings.
    # Strategy:
    # 1) If sending on the same interface as receiver (common in local tests), use the interface MAC.
    # 2) Otherwise try ARP resolution for the IPv4 destination (may be slow).
    try:
        from scapy.all import get_if_hwaddr, getmacbyip
    except Exception:
        get_if_hwaddr = None
        getmacbyip = None

    dst_mac = None
    # 1) interface MAC
    try:
        if get_if_hwaddr is not None:
            dst_mac = get_if_hwaddr(iface)
    except Exception:
        dst_mac = None

    # 2) try ARP resolve dst IP (best-effort)
    if dst_mac is None and getmacbyip is not None:
        try:
            mac = getmacbyip(IP_DST)
            if mac:
                dst_mac = mac
        except Exception:
            dst_mac = None

    if dst_mac:
        frame.dst = dst_mac

    next_send = time.time()
    while not stop_event.is_set():
        now = time.time()
        if now < next_send:
            time.sleep(min(next_send - now, 0.1))
            continue
        try:
            sendp(frame, iface=iface, verbose=False)
        except PermissionError:
            print(f"[SENDER] Permission error sending on {iface}. Are you root?")
            return
        except Exception as e:
            print(f"[SENDER] Error sending packet on {iface}: {e}")
        next_send += period
        if next_send < time.time():
            next_send = time.time() + period


# Improved CounterStat using sample history + regression
class CounterStat:
    def __init__(self):
        self.lock = threading.Lock()
        # history of (ts_ns, bytes) tuples for regression/averaging
        self.samples = deque(maxlen=SAMPLES_KEEP)
        # last computed metrics
        self.instant_mbps: Optional[float] = None
        self.regress_mbps: Optional[float] = None
        self.ewma_mbps: Optional[float] = None
        # last seen wall time
        self.last_seen_wall: float = 0.0

    def update(self, bytes_val: int, ts_ns: int, wall_time: float, alpha: float):
        with self.lock:
            # append sample (ns, bytes)
            self.samples.append((ts_ns, bytes_val))
            self.last_seen_wall = wall_time

            # compute instant using last two samples if available
            if len(self.samples) >= 2:
                (t1, b1), (t2, b2) = (self.samples[-2], self.samples[-1])
                delta_bytes = b2 - b1
                delta_ns = t2 - t1
                if delta_ns > 0 and delta_bytes >= 0:
                    bits_per_ns = (delta_bytes * 8) / delta_ns
                    self.instant_mbps = bits_per_ns * 1000.0
                else:
                    self.instant_mbps = None
            else:
                self.instant_mbps = None

            # regression over samples (least-squares) to get slope bytes/ns
            if len(self.samples) >= 2:
                # compute means
                xs = [s[0] for s in self.samples]
                ys = [s[1] for s in self.samples]
                n = len(xs)
                mean_x = sum(xs) / n
                mean_y = sum(ys) / n
                num = sum((xs[i] - mean_x) * (ys[i] - mean_y) for i in range(n))
                den = sum((xs[i] - mean_x) ** 2 for i in range(n))
                if den > 0:
                    slope_bytes_per_ns = num / den
                    self.regress_mbps = slope_bytes_per_ns * 8.0 * 1000.0
                else:
                    self.regress_mbps = None
            else:
                self.regress_mbps = None

            # update EWMA using instant (if available)
            value_for_ewma = None
            if self.instant_mbps is not None:
                value_for_ewma = self.instant_mbps
            elif self.regress_mbps is not None:
                value_for_ewma = self.regress_mbps

            if value_for_ewma is not None:
                if self.ewma_mbps is None:
                    self.ewma_mbps = value_for_ewma
                else:
                    self.ewma_mbps = alpha * value_for_ewma + (1 - alpha) * self.ewma_mbps


# Globals
flows_stats: Dict[int, CounterStat] = {}
ports_stats: Dict[int, CounterStat] = {}
stats_lock = threading.Lock()

# Logging
log_handle = None
log_writer = None
log_lock = threading.Lock()


def open_log(path: str):
    global log_handle, log_writer
    log_handle = open(path, "a", newline="")
    log_writer = csv.writer(log_handle)
    if log_handle.tell() == 0:
        log_writer.writerow([
            "wall_time", "index_flow", "index_port", "bytes_flow", "bytes_port", "timestamp_ns",
            "port_field", "pktLen",
            "qID_port", "qDepth_port", "qTime_port",
            "qID_flow", "qDepth_flow", "qTime_flow"
        ])
    log_handle.flush()


def close_log():
    global log_handle
    if log_handle:
        log_handle.close()


# Parse monitor_h (big-endian)
def parse_monitor_h(raw: bytes, monitor_h_off: int):
    off = monitor_h_off
    if len(raw) < off + MONITOR_H_LEN:
        raise ValueError("monitor_h incomplete")

    bytes_flow = struct.unpack("!Q", raw[off:off+8])[0]
    bytes_port = struct.unpack("!Q", raw[off+8:off+16])[0]
    ts_bytes = raw[off+16:off+22]
    timestamp_ns = int.from_bytes(ts_bytes, byteorder="big")
    port_pad = struct.unpack("!H", raw[off+22:off+24])[0]
    port_field = (port_pad >> 7) & 0x1FF
    pktLen = struct.unpack("!H", raw[off+24:off+26])[0]
    qID_port = struct.unpack("!I", raw[off+26:off+30])[0]
    qDepth_port = struct.unpack("!I", raw[off+30:off+34])[0]
    qTime_port = struct.unpack("!I", raw[off+34:off+38])[0]
    qID_flow = struct.unpack("!I", raw[off+38:off+42])[0]
    qDepth_flow = struct.unpack("!I", raw[off+42:off+46])[0]
    qTime_flow = struct.unpack("!I", raw[off+46:off+50])[0]

    return {
        "bytes_flow": bytes_flow,
        "bytes_port": bytes_port,
        "timestamp_ns": timestamp_ns,
        "port_field": port_field,
        "pktLen": pktLen,
        "qID_port": qID_port,
        "qDepth_port": qDepth_port,
        "qTime_port": qTime_port,
        "qID_flow": qID_flow,
        "qDepth_flow": qDepth_flow,
        "qTime_flow": qTime_flow
    }


# Receiver callback
def packet_received_callback(pkt, ewma_alpha: float):
    raw = bytes(pkt)
    if len(raw) < ETH_HDR_LEN + MONITOR_INST_LEN + 20:
        return

    mon_inst_off = ETH_HDR_LEN
    mon_inst_end = mon_inst_off + MONITOR_INST_LEN
    if len(raw) < mon_inst_end:
        return

    mon_inst_bytes = raw[mon_inst_off:mon_inst_end]
    try:
        index_flow, index_port = struct.unpack("!II", mon_inst_bytes[:8])
    except Exception:
        return

    ip_off = mon_inst_end
    if len(raw) < ip_off + 1:
        return
    version_ihl = raw[ip_off]
    ihl = version_ihl & 0x0F
    ip_header_len = ihl * 4
    if ip_header_len < 20:
        return
    monitor_h_off = ip_off + ip_header_len
    if len(raw) < monitor_h_off + MONITOR_H_LEN:
        return

    try:
        mh = parse_monitor_h(raw, monitor_h_off)
    except Exception:
        return

    wall_time = time.time()

    with stats_lock:
        fs = flows_stats.get(index_flow)
        if fs is None:
            fs = CounterStat()
            flows_stats[index_flow] = fs
        fs.update(mh["bytes_flow"], mh["timestamp_ns"], wall_time, ewma_alpha)

        ps = ports_stats.get(index_port)
        if ps is None:
            ps = CounterStat()
            ports_stats[index_port] = ps
        ps.update(mh["bytes_port"], mh["timestamp_ns"], wall_time, ewma_alpha)

    if log_writer is not None:
        with log_lock:
            log_writer.writerow([
                time.time(), index_flow, index_port, mh["bytes_flow"], mh["bytes_port"], mh["timestamp_ns"],
                mh["port_field"], mh["pktLen"],
                mh["qID_port"], mh["qDepth_port"], mh["qTime_port"],
                mh["qID_flow"], mh["qDepth_flow"], mh["qTime_flow"]
            ])
            log_handle.flush()


# Receiver thread
def receiver_thread(iface: str, stop_event: threading.Event, ewma_alpha: float):
    bpf = f"ether proto 0x{ETH_TYPE_MON:04x}"
    def _prn(pkt):
        packet_received_callback(pkt, ewma_alpha)
    try:
        while not stop_event.is_set():
            sniff(iface=iface, prn=_prn, filter=bpf, timeout=1, store=False)
    except PermissionError:
        print(f"[RECV] Permission error sniffing on {iface}. Are you root?")
    except Exception as e:
        print(f"[RECV] Sniffing error on {iface}: {e}")


# Dashboard printer with aligned columns
def dashboard_loop(refresh_interval: float, inactive_timeout: float):
    """
    Dashboard printer using curses when stdout is a tty for reliable screen updates.
    Falls back to ANSI clears if curses is unavailable or stdout is not a TTY.
    """
    def _draw_with_curses(stdscr):
        curses = __import__('curses')
        # basic curses setup
        stdscr.nodelay(True)
        stdscr.clear()
        try:
            while True:
                now = time.time()
                stdscr.erase()
                header = f"Monitor dashboard - {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(now))}"
                stdscr.addstr(0, 0, header)
                stdscr.addstr(1, 0, f"Showing items seen within last {inactive_timeout} seconds. Refresh every {refresh_interval}s.")

                # Column headings
                hdr = "ID    LastBytes      LastTs(ns)          Inst(Mbps)  Reg(Mbps)   EWMA(Mbps)  LastSeen(s)"
                stdscr.addstr(3, 0, "Flows:")
                stdscr.addstr(4, 0, hdr)

                row = 5
                with stats_lock:
                    active_flows = []
                    for fid, st in list(flows_stats.items()):
                        with st.lock:
                            last_seen_ago = now - st.last_seen_wall if st.last_seen_wall else 1e9
                            if last_seen_ago <= inactive_timeout:
                                active_flows.append((fid, st, last_seen_ago))
                            else:
                                flows_stats.pop(fid, None)

                    def flow_key(item):
                        st = item[1]
                        return st.regress_mbps if st.regress_mbps is not None else (st.ewma_mbps or st.instant_mbps or 0.0)

                    active_flows.sort(key=flow_key, reverse=True)

                    for fid, st, last_seen_ago in active_flows:
                        with st.lock:
                            lb = st.samples[-1][1] if st.samples else 0
                            lts = st.samples[-1][0] if st.samples else 0
                            inst = f"{st.instant_mbps:.3f}" if st.instant_mbps is not None else "-"
                            reg = f"{st.regress_mbps:.3f}" if st.regress_mbps is not None else "-"
                            ewma = f"{st.ewma_mbps:.3f}" if st.ewma_mbps is not None else "-"
                            line = f"{fid:<5} {lb:>12d} {lts:>18d} {inst:>12} {reg:>12} {ewma:>12} {last_seen_ago:>11.2f}"
                            try:
                                stdscr.addstr(row, 0, line)
                            except Exception:
                                # line won't fit; ignore
                                pass
                            row += 1
                            if row > curses.LINES - 4:
                                break

                # Ports
                row += 1
                stdscr.addstr(row, 0, "Ports:")
                row += 1
                stdscr.addstr(row, 0, hdr)
                row += 1

                with stats_lock:
                    active_ports = []
                    for pid, st in list(ports_stats.items()):
                        with st.lock:
                            last_seen_ago = now - st.last_seen_wall if st.last_seen_wall else 1e9
                            if last_seen_ago <= inactive_timeout:
                                active_ports.append((pid, st, last_seen_ago))
                            else:
                                ports_stats.pop(pid, None)

                    def port_key(item):
                        st = item[1]
                        return st.regress_mbps if st.regress_mbps is not None else (st.ewma_mbps or st.instant_mbps or 0.0)

                    active_ports.sort(key=port_key, reverse=True)

                    for pid, st, last_seen_ago in active_ports:
                        with st.lock:
                            lb = st.samples[-1][1] if st.samples else 0
                            lts = st.samples[-1][0] if st.samples else 0
                            inst = f"{st.instant_mbps:.3f}" if st.instant_mbps is not None else "-"
                            reg = f"{st.regress_mbps:.3f}" if st.regress_mbps is not None else "-"
                            ewma = f"{st.ewma_mbps:.3f}" if st.ewma_mbps is not None else "-"
                            line = f"{pid:<5} {lb:>12d} {lts:>18d} {inst:>12} {reg:>12} {ewma:>12} {last_seen_ago:>11.2f}"
                            try:
                                stdscr.addstr(row, 0, line)
                            except Exception:
                                pass
                            row += 1
                            if row > curses.LINES - 2:
                                break

                stdscr.refresh()
                # sleep a bit but allow quick exit if key pressed
                for i in range(int(max(1, refresh_interval*10))):
                    try:
                        k = stdscr.getch()
                        if k == ord('q'):
                            return
                    except Exception:
                        pass
                    time.sleep(refresh_interval/10.0)
        finally:
            # ensure we restore terminal settings on exit
            try:
                import curses
                curses.nocbreak(); curses.echo(); curses.endwin()
            except Exception:
                pass

    # choose method: curses if tty, else ANSI fallback
    try:
        if sys.stdout.isatty():
            import curses
            curses.wrapper(_draw_with_curses)
        else:
            # fallback to simple ANSI clear method
            while True:
                now = time.time()
                print('[2J[H', end='')
                sys.stdout.flush()
                print(f"Monitor dashboard - {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(now))}")
                print(f"Showing items seen within last {inactive_timeout} seconds. Refresh every {refresh_interval}s.")
                # headers
                print("Flows:")
                print("ID    LastBytes      LastTs(ns)          Inst(Mbps)  Reg(Mbps)   EWMA(Mbps)  LastSeen(s)")

                with stats_lock:
                    active_flows = []
                    for fid, st in list(flows_stats.items()):
                        with st.lock:
                            last_seen_ago = now - st.last_seen_wall if st.last_seen_wall else 1e9
                            if last_seen_ago <= inactive_timeout:
                                active_flows.append((fid, st, last_seen_ago))
                            else:
                                flows_stats.pop(fid, None)

                    def flow_key(item):
                        st = item[1]
                        return st.regress_mbps if st.regress_mbps is not None else (st.ewma_mbps or st.instant_mbps or 0.0)

                    active_flows.sort(key=flow_key, reverse=True)

                    for fid, st, last_seen_ago in active_flows:
                        with st.lock:
                            lb = st.samples[-1][1] if st.samples else 0
                            lts = st.samples[-1][0] if st.samples else 0
                            inst = f"{st.instant_mbps:.3f}" if st.instant_mbps is not None else "-"
                            reg = f"{st.regress_mbps:.3f}" if st.regress_mbps is not None else "-"
                            ewma = f"{st.ewma_mbps:.3f}" if st.ewma_mbps is not None else "-"
                            print(f"{fid:<5} {lb:>12d} {lts:>18d} {inst:>12} {reg:>12} {ewma:>12} {last_seen_ago:>11.2f}")

                print("Ports:")
                print("ID    LastBytes      LastTs(ns)          Inst(Mbps)  Reg(Mbps)   EWMA(Mbps)  LastSeen(s)")

                with stats_lock:
                    active_ports = []
                    for pid, st in list(ports_stats.items()):
                        with st.lock:
                            last_seen_ago = now - st.last_seen_wall if st.last_seen_wall else 1e9
                            if last_seen_ago <= inactive_timeout:
                                active_ports.append((pid, st, last_seen_ago))
                            else:
                                ports_stats.pop(pid, None)

                    def port_key(item):
                        st = item[1]
                        return st.regress_mbps if st.regress_mbps is not None else (st.ewma_mbps or st.instant_mbps or 0.0)

                    active_ports.sort(key=port_key, reverse=True)

                    for pid, st, last_seen_ago in active_ports:
                        with st.lock:
                            lb = st.samples[-1][1] if st.samples else 0
                            lts = st.samples[-1][0] if st.samples else 0
                            inst = f"{st.instant_mbps:.3f}" if st.instant_mbps is not None else "-"
                            reg = f"{st.regress_mbps:.3f}" if st.regress_mbps is not None else "-"
                            ewma = f"{st.ewma_mbps:.3f}" if st.ewma_mbps is not None else "-"
                            print(f"{pid:<5} {lb:>12d} {lts:>18d} {inst:>12} {reg:>12} {ewma:>12} {last_seen_ago:>11.2f}")

                time.sleep(refresh_interval)
    except KeyboardInterrupt:
        return


def main():
    parser = argparse.ArgumentParser(description="Monitor throughput from monitor packets (live dashboard).")
    parser.add_argument("--mode", choices=["send", "recv", "both"], default="both", help="mode: send, recv or both (default both)")
    parser.add_argument("--send-if", "-s", default=DEFAULT_SEND_IF, help=f"send interface (default {DEFAULT_SEND_IF})")
    parser.add_argument("--recv-if", "-r", default=DEFAULT_RECV_IF, help=f"receive interface (default {DEFAULT_RECV_IF})")
    parser.add_argument("--file", "-f", required=False, help="input flows file (required for send or both modes)")
    parser.add_argument("--log", help="optional CSV log path (append)")
    parser.add_argument("--refresh", type=float, default=1.0, help="dashboard refresh interval seconds (default 1.0)")
    parser.add_argument("--inactive", type=float, default=5.0, help="inactive timeout seconds (default 5.0)")
    parser.add_argument("--alpha", type=float, default=DEFAULT_EWMA_ALPHA, help="EWMA alpha for smoothing (default 0.3)")
    args = parser.parse_args()

    mode = args.mode
    send_iface = args.send_if
    recv_iface = args.recv_if
    flows_file = args.file
    log_path = args.log
    refresh_interval = args.refresh
    inactive_timeout = args.inactive
    ewma_alpha = args.alpha

    conf.verb = 0

    # validate
    if mode in ("send", "both") and not flows_file:
        print("Error: --file is required when mode is 'send' or 'both'")
        return

    flows = []
    if flows_file:
        try:
            flows = parse_flows_file(flows_file)
        except Exception as e:
            print(f"[MAIN] Failed to parse flows file '{flows_file}': {e}")
            return

    if mode in ("send", "both") and not flows:
        print("[MAIN] No flows found in the input file.")
        return

    if mode in ("recv", "both") and log_path:
        open_log(log_path)
        print(f"[MAIN] Logging enabled -> {log_path}")

    stop_event = threading.Event()

    # start receiver if requested
    recv_t = None
    if mode in ("recv", "both"):
        recv_t = threading.Thread(target=receiver_thread, args=(recv_iface, stop_event, ewma_alpha), daemon=True)
        recv_t.start()
        print(f"[MAIN] Receiver started on {recv_iface}")

    # start senders if requested
    sender_threads = []
    if mode in ("send", "both"):
        for f in flows:
            t = threading.Thread(target=flow_sender_thread, args=(send_iface, f, stop_event), daemon=True)
            sender_threads.append(t)
            t.start()
            print(f"[MAIN] Started sender for flow={f['flow']} port={f['port']} period={f['period']} on {send_iface}")

    try:
        if mode == "send":
            # just keep running until interrupted
            while True:
                time.sleep(1)
        else:
            # mode is recv or both: show dashboard
            dashboard_loop(refresh_interval, inactive_timeout)
    except KeyboardInterrupt:
        pass
    finally:
        stop_event.set()
        # allow threads to terminate
        time.sleep(0.2)
        close_log()


if __name__ == "__main__":
    main()

