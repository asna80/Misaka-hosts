#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
hosts-aggregator
================
把多个上游 hosts 源合并成一份「自己验证过」的 hosts 文件。

核心原则（解决「去重保留哪个」的争议）：
  1. 不按上游的更新时间排序，因为各源时间格式/时区不一致，且 raw CDN 有缓存。
  2. IPv4：对每个候选 IP 做真实探测（TCP:443 + SNI + 证书校验），活的、快的胜出。
  3. IPv6：CI 运行环境普遍没有 IPv6 出口，无法探测，因此改用 DoH 交叉验证：
     只保留「当前权威 DNS 仍然返回这个 AAAA」或「当前 AAAA 就是它」的记录，
     从而过滤掉上游遗留的过期 IPv6。
  4. 全部候选都失败时不清空：沿用上一次发布的值（carry），连续失败超过 N 次才丢弃。
  5. 每个域名最终只写 1 个 IPv4 + 1 个 IPv6，避免「写多条更保险」反而让客户端死等坏 IP。

只依赖 Python 标准库。
"""
import argparse
import asyncio
import base64
import csv
import ipaddress
import json
import os
import random
import re
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

# ---------------------------------------------------------------- 常量

UA = "hosts-aggregator/1.0 (+https://github.com)"

# 域名合法性：至少一个点，标签 1-63，不含下划线/通配符
HOST_RE = re.compile(
    r"^(?=.{4,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)

# 这些域名即使上游没给 IPv6，也强制去查一次 AAAA（已知双栈的关键站点）
V6_ALWAYS = {
    "www.gog.com",
    "gog.com",
    "auth.gog.com",
    "www.gogalaxy.com",
    "raw.githubusercontent.com",
    "cdn.cloudflare.steamstatic.com",
    "client-update.akamai.steamstatic.com",
    "www.ubisoft.com",
}

# DoH 解析器分两类：
#   trusted = 海外解析器，AAAA 不会被污染，作为「真相」来源
#   cn      = 国内解析器，对被墙域名的 AAAA 会返回伪造地址（实测 www.google.com -> 2001::1），
#             只能用来交叉核对上游已有记录，不能作为新记录的来源
DOH_TRUSTED = [
    "https://cloudflare-dns.com/dns-query",
    "https://dns.google/resolve",
]

# 近端解析器：出口在香港/日本，返回的 CDN 边缘最贴近国内。
# 它们不在墙内，答案不会被污染，所以既当「就近取值」也当 trusted 的备用。
DOH_NEAR = [
    "https://hk-hkg.doh.sb/dns-query",
    "https://jp-kix.doh.sb/dns-query",
]

# GFW DNS 污染的经典返回地址（A 记录）。命中这些的一律不当真。
POISON_V4 = {
    "128.121.146.109", "8.7.198.45", "59.24.3.173", "203.98.7.65",
    "243.185.187.39", "37.61.54.158", "46.82.174.68", "78.16.49.15",
    "93.46.8.89", "159.106.121.75", "187.59.34.166", "202.181.7.253",
    "4.36.66.178", "8.7.198.46", "159.24.3.173",
}

MIRROR_TEMPLATES = [
    "https://ghproxy.net/{}",
    "https://gh-proxy.com/{}",
    "https://ghfast.top/{}",
    "https://gh.llkk.cc/{}",
]

BLOCKED_NETS_V4 = [
    ipaddress.ip_network(n)
    for n in (
        "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
        "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.168.0.0/16",
        "198.18.0.0/15", "224.0.0.0/4", "240.0.0.0/4",
    )
]

BLOCKED_NETS_V6 = [
    ipaddress.ip_network(n)
    for n in (
        "::/128", "::1/128", "64:ff9b::/96", "100::/64", "2001::/32",  # Teredo：国内被污染的 AAAA 常见产物
        "2002::/16",                                                    # 6to4
        "fc00::/7", "fe80::/10", "ff00::/8",
    )
]

# 关键域名：探活全部失败时也不允许从结果里消失（宁可保留待验证 IP，也不能让这些域名失去记录）。
# 这些是你明确点名的刚需：GitHub、Steam、GOG、Epic。
CRITICAL = {
    "github.com", "api.github.com", "gist.github.com", "codeload.github.com",
    "raw.githubusercontent.com", "objects.githubusercontent.com",
    "github.githubassets.com", "avatars.githubusercontent.com",
    "store.steampowered.com", "steamcommunity.com", "api.steampowered.com",
    "cdn.akamai.steamstatic.com", "steamcdn-a.akamaihd.net",
    "www.gog.com", "gog.com", "launcher.epicgames.com", "www.epicgames.com",
}

CARRY_LIMIT = 7          # 连续多少轮探测不到才丢弃
TLS_PORT = 443


def log(msg):
    print(msg, flush=True)


def norm_url(url):
    """把 GitHub blob 页面改写成 raw 地址。"""
    m = re.match(r"^https://github\.com/([^/]+)/([^/]+)/blob/(.+)$", url)
    if m:
        user, repo, rest = m.groups()
        return f"https://raw.githubusercontent.com/{user}/{repo}/{rest}"
    return url


def mirror_urls(url):
    """直连 + 若干镜像，作为下载失败时的回退（国内直连 raw 常常不通）。"""
    out = [url]
    if "raw.githubusercontent.com/" in url:
        path = url.split("raw.githubusercontent.com/", 1)[1]
        base = "https://raw.githubusercontent.com/" + path
        for tpl in MIRROR_TEMPLATES:
            out.append(tpl.format(base))
    elif "/releases/download/" in url:
        for tpl in MIRROR_TEMPLATES:
            out.append(tpl.format(url))
    return out


def read_sources(path):
    rows, seen = [], set()
    with open(path, encoding="utf-8-sig") as f:
        for raw in f:
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            parts = [p.strip() for p in line.split("|")]
            if len(parts) != 3:
                log(f"[warn] sources.txt 行格式错误，已跳过: {line[:60]}")
                continue
            tier, name, url = parts
            if name in seen:
                log(f"[warn] 源重名，已跳过: {name}")
                continue
            seen.add(name)
            rows.append({"tier": int(tier), "name": name, "url": norm_url(url)})
    return rows


def http_get(url, timeout=30):
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": UA,
            "Accept": "text/plain,*/*",
            "Accept-Encoding": "identity",
            "Cache-Control": "no-cache",
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


# ---------------------------------------------------------------- 抓取

def fetch_source(src):
    """返回 (name, tier, text|None, info dict)。失败时对镜像做两轮重试。"""
    info = {"bytes": 0, "url_used": None, "error": None}
    urls = mirror_urls(src["url"])
    for attempt in range(2):
        for url in urls:
            try:
                data = http_get(url, timeout=20 if "releases" in url or "github.com" in url else 15)
                if not data:
                    raise ValueError("empty body")
                text = data.decode("utf-8-sig", "replace")
                low = text[:400].lower()
                if "<!doctype html" in low or "<html" in low:
                    raise ValueError("got HTML (可能是 blob 页面或错误页)")
                info["bytes"] = len(data)
                info["url_used"] = url
                return src["name"], src["tier"], text, info
            except Exception as e:  # noqa: BLE001
                info["error"] = f"{type(e).__name__}: {e}"
                continue
        if attempt == 0:
            time.sleep(2)
    return src["name"], src["tier"], None, info


def fetch_all(sources, workers=8):
    out = {}
    with ThreadPoolExecutor(max_workers=workers) as ex:
        for name, tier, text, info in ex.map(fetch_source, sources):
            out[name] = (tier, text, info)
            flag = "OK " if text else "ERR"
            log(f"[fetch] {flag} {name:14} {(info['bytes'] or 0):>9} B"
                + (f"  <- {info['error']}" if info["error"] and not text else ""))
    return out


# ---------------------------------------------------------------- 解析

def usable_v4(ip):
    try:
        a = ipaddress.IPv4Address(ip)
    except ValueError:
        return False
    return not any(a in n for n in BLOCKED_NETS_V4)


FORGED_V6_NETS = [
    ipaddress.ip_network(n) for n in ("2001::/32", "2002::/16")
]

# GFW 对 AAAA 的伪造应答经常指向 Facebook 网段（实测 000webhost.com 会返回 2a03:2880::/32）。
# 域名本身不属于 Facebook 家族时，一律视为伪造。
FACEBOOK_V6 = ipaddress.ip_network("2a03:2880::/32")
FB_HINTS = ("facebook", "fbcdn", "fb.com", "fbsbx", "instagram", "whatsapp", "meta.com")


def forged_v6(ip, domain):
    try:
        a = ipaddress.IPv6Address(ip)
    except ValueError:
        return True
    if any(a in n for n in FORGED_V6_NETS):
        return True
    if a in FACEBOOK_V6 and not any(h in domain for h in FB_HINTS):
        return True
    return False


def usable_v6(ip):
    try:
        a = ipaddress.IPv6Address(ip)
    except ValueError:
        return False
    if a.is_loopback or a.is_link_local or a.is_multicast or a.is_unspecified or a.ipv4_mapped:
        return False
    return not any(a in n for n in BLOCKED_NETS_V6)


def parse_source(text, name, tier, cand, stats):
    """把一份 hosts 文本解析进 cand[domain][family][ip] = {sources:set, tier:int}"""
    kept = 0
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip().replace("\t", " ")
        if not line:
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        ip = parts[0]
        if ":" in ip:
            fam = "6"
            if not usable_v6(ip):
                continue
        else:
            fam = "4"
            if not usable_v4(ip):
                continue
        for host in parts[1:]:
            host = host.strip().strip(".").lower()
            if len(host) < 4 or not HOST_RE.match(host):
                continue
            d = cand.setdefault(host, {"4": {}, "6": {}})
            slot = d[fam].setdefault(ip, {"srcs": set(), "tier": 9})
            slot["srcs"].add(name)
            slot["tier"] = min(slot["tier"], tier)
            kept += 1
    stats[name] = {"entries": kept}
    return kept


# ---------------------------------------------------------------- 探测

_SSL_CTX = None


def make_ssl_ctx():
    """复用同一个 SSLContext：每个 probe 新建一次会反复解析 CA 包，慢 5-10 倍。"""
    global _SSL_CTX
    if _SSL_CTX is None:
        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        _SSL_CTX = ctx
    return _SSL_CTX


async def tls_probe(ip, host, timeout):
    """TCP:443 + SNI + 证书校验。返回 ("ok"|"cert"|"fail", ms)"""
    t0 = time.monotonic()
    ctx = make_ssl_ctx()
    writer = None
    try:
        _r, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, TLS_PORT, ssl=ctx, server_hostname=host),
            timeout=timeout,
        )
        ms = (time.monotonic() - t0) * 1000
        return "ok", ms
    except ssl.SSLCertVerificationError:
        return "cert", (time.monotonic() - t0) * 1000
    except (asyncio.TimeoutError, TimeoutError):
        return "timeout", (time.monotonic() - t0) * 1000
    except Exception:  # noqa: BLE001
        return "fail", (time.monotonic() - t0) * 1000
    finally:
        if writer is not None:
            try:
                writer.close()
            except Exception:  # noqa: BLE001
                pass


async def tcp_probe(ip, port, timeout):
    """只判断 TCP 是否连得上（用于区分「IP 死了」和「TLS/证书不对」）。"""
    t0 = time.monotonic()
    writer = None
    try:
        _r, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        return True, (time.monotonic() - t0) * 1000
    except Exception:  # noqa: BLE001
        return False, (time.monotonic() - t0) * 1000
    finally:
        if writer is not None:
            try:
                writer.close()
            except Exception:  # noqa: BLE001
                pass


async def run_probes(tasks, concurrency, timeout, deadline, tps=None):
    """tasks: list of (host, ip)。

    tps 为 None 时做 TLS(SNI+证书) 探测；传入一个 port 时只做 TCP 连通性探测。
    返回 {(host, ip): (status, ms)}，status ∈ ok/cert/timeout/fail/tcp/tcpfail/skip
    """
    sem = asyncio.Semaphore(concurrency)
    results = {}
    stop = asyncio.Event()

    async def one(host, ip):
        if stop.is_set() or time.monotonic() > deadline:
            stop.set()
            return
        async with sem:
            if time.monotonic() > deadline:
                return
            if tps is None:
                st, ms = await tls_probe(ip, host, timeout)
            else:
                ok, ms = await tcp_probe(ip, tps, timeout)
                st = "tcp" if ok else "tcpfail"
            results[(host, ip)] = (st, ms)

    await asyncio.gather(*(one(h, i) for h, i in tasks))
    return results


# ---------------------------------------------------------------- DoH

_DOH_STATE = {"trusted_fail": 0}
DOH_TRUSTED_FAIL_LIMIT = 25     # 海外解析器连续失败这么多次后就不再尝试（避免整轮卡死）

# 每个 DoH 端点独立熔断：连续失败到阈值就整轮跳过它。
# 否则一个不可达的端点 × 上万个域名 = 直接把 Action 拖到超时。
_DOH_FAIL = {}
DOH_ENDPOINT_FAIL_LIMIT = 8


def _doh_try(host, rtype, base):
    if _DOH_FAIL.get(base, 0) >= DOH_ENDPOINT_FAIL_LIMIT:
        raise RuntimeError("breaker open: " + base)
    try:
        ips = _doh_query(host, rtype, base)
        _DOH_FAIL[base] = 0
        return ips
    except Exception:
        _DOH_FAIL[base] = _DOH_FAIL.get(base, 0) + 1
        raise


def _dns_packet(host, rtype):
    """构造 RFC 1035 查询报文（QTYPE=1/28）。"""
    tid = random.randint(0, 0xFFFF)
    header = tid.to_bytes(2, "big") + b"\x01\x00" + b"\x00\x01" + b"\x00\x00" + b"\x00\x00" + b"\x00\x00"
    q = b""
    for label in host.strip(".").split("."):
        b = label.encode("idna") if label else b""
        if not b or len(b) > 63:
            raise ValueError("bad label")
        q += bytes([len(b)]) + b
    q += b"\x00"
    q += (1 if rtype == "A" else 28).to_bytes(2, "big") + b"\x00\x01"
    return header + q


def _dns_parse(data, want_type):
    """解析响应里的 A/AAAA（处理域名压缩指针）。"""
    if len(data) < 12:
        return []
    qd = int.from_bytes(data[4:6], "big")
    an = int.from_bytes(data[6:8], "big")
    pos = 12

    def skip_name(p):
        while p < len(data):
            ln = data[p]
            if ln == 0:
                return p + 1
            if ln & 0xC0 == 0xC0:
                return p + 2
            p += 1 + ln
        return p

    for _ in range(qd):
        pos = skip_name(pos)
        pos += 4
    out = []
    for _ in range(an):
        pos = skip_name(pos)
        if pos + 10 > len(data):
            break
        rtype = int.from_bytes(data[pos:pos + 2], "big")
        rdlen = int.from_bytes(data[pos + 8:pos + 10], "big")
        rdata = data[pos + 10: pos + 10 + rdlen]
        pos += 10 + rdlen
        if rtype != want_type:
            continue
        if want_type == 1 and rdlen == 4:
            out.append(".".join(str(b) for b in rdata))
        elif want_type == 28 and rdlen == 16:
            out.append(":".join(f"{int.from_bytes(rdata[i:i + 2], 'big'):x}"
                                for i in range(0, 16, 2)))
    return out


def _doh_wire(host, rtype, base):
    """标准 DoH（RFC 8484）。GET 不行就退 POST —— 有些服务只收 POST。"""
    pkt = _dns_packet(host, rtype)
    want = 1 if rtype == "A" else 28
    b64 = base64.urlsafe_b64encode(pkt).decode().rstrip("=")
    try:
        req = urllib.request.Request(
            f"{base}?dns={b64}",
            headers={"User-Agent": UA, "Accept": "application/dns-message"},
        )
        with urllib.request.urlopen(req, timeout=6) as r:
            return _dns_parse(r.read(), want)
    except Exception:  # noqa: BLE001
        pass
    req = urllib.request.Request(
        base,
        data=pkt,
        headers={
            "User-Agent": UA,
            "Accept": "application/dns-message",
            "Content-Type": "application/dns-message",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=6) as r:
        return _dns_parse(r.read(), want)


def _doh_query(host, rtype, base):
    """先试标准 wireformat；不行再回退 JSON 接口（AliDNS/CF 的 ?name= 端点）。"""
    try:
        return _doh_wire(host, rtype, base)
    except Exception:  # noqa: BLE001
        pass
    url = f"{base}?name={urllib.parse.quote(host)}&type={rtype}"
    req = urllib.request.Request(
        url, headers={"User-Agent": UA, "Accept": "application/dns-json"}
    )
    with urllib.request.urlopen(req, timeout=5) as r:
        data = json.loads(r.read().decode("utf-8", "replace"))
    want = 28 if rtype == "AAAA" else 1
    out = []
    for ans in data.get("Answer", []) or []:
        if ans.get("type") == want:
            v = str(ans.get("data", "")).strip()
            if v:
                out.append(v)
    return out


def doh_lookup(host, rtype="AAAA"):
    """返回 (ips, kind)。kind='trusted' 表示来自海外/近端（非墙内）解析器。"""
    if _DOH_STATE["trusted_fail"] < DOH_TRUSTED_FAIL_LIMIT:
        for base in DOH_TRUSTED:
            try:
                ips = _doh_try(host, rtype, base)
                _DOH_STATE["trusted_fail"] = 0
                return ips, "trusted"
            except Exception:  # noqa: BLE001
                _DOH_STATE["trusted_fail"] += 1
                continue
    # 海外不可达时，用香港/日本节点兜底（同样不在墙内，答案可信）
    for base in DOH_NEAR:
        try:
            return _doh_try(host, rtype, base), "trusted"
        except Exception:  # noqa: BLE001
            continue
    raise RuntimeError("all DoH endpoints failed")


def doh_near_many(hosts, workers=40, rtype="A"):
    """用「近端」解析器批量查 A，并把多个解析器的答案**合并成候选池**。

    关键：不采信单一解析器的答案。国内解析器对被墙域名会返回污染地址，
    但污染地址通常拿不出该域名的合法证书 —— 交给后续证书复核投票即可淘汰。
    """
    out = {}

    def work(h):
        ips = []
        for base in DOH_NEAR:
            try:
                for ip in _doh_try(h, rtype, base):
                    if ip not in ips:
                        ips.append(ip)
            except Exception:  # noqa: BLE001
                continue
        return h, ips

    with ThreadPoolExecutor(max_workers=workers) as ex:
        for h, ips in ex.map(work, hosts):
            out[h] = ips
    return out


def doh_many(hosts, workers=40, rtype="AAAA"):
    out = {}

    def work(h):
        try:
            ips, kind = doh_lookup(h, rtype)
            return h, ips, kind, None
        except Exception as e:  # noqa: BLE001
            return h, None, None, str(e)

    with ThreadPoolExecutor(max_workers=workers) as ex:
        for h, ips, kind, err in ex.map(work, hosts):
            out[h] = (ips, kind, err)
    return out


# ---------------------------------------------------------------- 上一版

def load_prev(outdir):
    p = os.path.join(outdir, "prev.json")
    if not os.path.exists(p):
        return {}
    try:
        with open(p, encoding="utf-8") as f:
            return json.load(f)
    except Exception:  # noqa: BLE001
        return {}


# ---------------------------------------------------------------- 主流程

GEOSITE_BASE = "https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/"


_FETCH_STATE = {"raw_fail": 0}


def _http_get_any(url, timeout=20, mirrors=2):
    """抓一个文件，失败时走镜像。

    直连 raw 在国内常被墙：失败 3 次后整轮不再尝试它，直接走镜像。
    镜像首次可能慢（缓存未命中），所以镜像超时给足；并发靠调用方拉高。
    """
    urls = mirror_urls(url)[: 1 + mirrors]
    if _FETCH_STATE["raw_fail"] >= 3 and urls and "raw.githubusercontent.com" in urls[0]:
        urls = urls[1:]
    last = None
    for u in urls:
        try:
            data = http_get(u, timeout=6 if "raw.githubusercontent" in u else timeout)
            _FETCH_STATE["raw_fail"] = 0
            return data
        except Exception as e:  # noqa: BLE001
            if "raw.githubusercontent" in u:
                _FETCH_STATE["raw_fail"] += 1
            last = e
    raise RuntimeError(f"fetch failed: {url} ({type(last).__name__})")


def load_geosite(cats, workers=16, log=print):
    """按 v2fly/domain-list-community 的语法展开域名清单。

    - include:xxx        → 递归展开（按层并行抓取，否则上百个类别文件会非常慢）
    - domain:xxx / xxx   → 后缀域名，取裸域名写 hosts
    - full:xxx           → 精确域名
    - @cn                → 中国专用（含国内 CDN），按要求**丢弃**
    - regexp: / keyword: → 无法枚举成 hostname，跳过并计数
    """
    domains, skipped, seen, per_cat = set(), 0, set(), {}
    pending = set(cats)

    def fetch_one(cat):
        try:
            raw = _http_get_any(GEOSITE_BASE + urllib.parse.quote(cat))
            return cat, raw.decode("utf-8", "replace")
        except Exception:  # noqa: BLE001
            return cat, None

    while pending:
        batch = sorted(c for c in pending if c not in seen)
        if not batch:
            break
        pending = set()
        with ThreadPoolExecutor(max_workers=workers) as ex:
            results = list(ex.map(fetch_one, batch))
        failed = sum(1 for _c, t in results if t is None)
        log(f"[geosite] 本层 {len(batch)} 个类别，失败 {failed}，累计域名 {len(domains)}")
        for cat, text in results:
            seen.add(cat)
            if text is None:
                log(f"[geosite] 跳过 {cat}（抓取失败）")
                continue
            got = 0
            for line in text.splitlines():
                line = line.split("#", 1)[0].strip()
                if not line:
                    continue
                parts = line.split()
                item, attrs = parts[0], parts[1:]
                if item.startswith("include:"):
                    if "@cn" in attrs:
                        skipped += 1
                        continue
                    inc = item[len("include:"):]
                    if inc not in seen:
                        pending.add(inc)
                    continue
                if item.startswith(("regexp:", "keyword:")):
                    skipped += 1
                    continue
                if "@cn" in attrs:
                    skipped += 1
                    continue
                if item.startswith("full:"):
                    d = item[5:]
                elif item.startswith("domain:"):
                    d = item[7:]
                else:
                    d = item
                d = d.strip().strip(".").lower()
                if HOST_RE.match(d):
                    domains.add(d)
                    got += 1
            per_cat[cat] = got
    log(f"[geosite] 展开 {len(seen)} 个类别，{len(domains)} 个域名")
    return domains, skipped, per_cat


DOCTOR_DOMAINS = [
    "store.steampowered.com", "www.gog.com", "github.com",
    "www.google.com", "www.youtube.com", "steamcommunity.com",
]


def doctor():
    """体检解析器：能不能用、延迟、是否在返回污染地址。"""
    resolvers = [(f"near    {u}", u) for u in DOH_NEAR] + \
                [(f"trusted {u}", u) for u in DOH_TRUSTED]
    log("解析器体检 —— 判据：同一 IP 覆盖多个无关域名 = 污染")
    for label, base in resolvers:
        row, lat = {}, []
        for d in DOCTOR_DOMAINS:
            t0 = time.time()
            try:
                ips = _doh_query(d, "A", base)
                row[d] = (ips[:2], None)
                lat.append(int((time.time() - t0) * 1000))
            except Exception as e:  # noqa: BLE001
                row[d] = ([], type(e).__name__)
        if all(not v[0] for v in row.values()):
            errs = {v[1] for v in row.values() if v[1]}
            log(f"  {label:42} 不可用（{list(errs)[0] if errs else '无答案'}）")
            continue
        ipdom = {}
        for d, (ips, _e) in row.items():
            for ip in ips:
                ipdom.setdefault(ip, set()).add(d)
        shared = sorted(ip for ip, ds in ipdom.items() if len(ds) >= 2)
        tag = "  <== 疑似污染: " + ", ".join(shared) if shared else ""
        avg = sum(lat) // len(lat) if lat else 0
        log(f"  {label:42} {avg:4}ms{tag}")
        for d in DOCTOR_DOMAINS:
            ips, err = row[d]
            log(f"      {d:26} {ips if ips else 'ERR ' + str(err)}")
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sources", default="sources.txt")
    ap.add_argument("--out", default="dist")
    ap.add_argument("--concurrency", type=int, default=256)
    ap.add_argument("--timeout", type=float, default=3.5)
    ap.add_argument("--max-probe", type=int, default=6, help="每个域名最多探几个 IPv4 候选")
    ap.add_argument("--max-seconds", type=int, default=3000, help="整轮探测时间预算")
    ap.add_argument("--limit", type=int, default=0, help="只处理前 N 个域名（调试用）")
    ap.add_argument("--focus", default="", help="只处理这些域名，逗号分隔（调试用）")
    ap.add_argument("--strict", action="store_true",
                    help="只信 TLS+证书验证通过的记录，关闭 tier1-grace / doh-resolved / critical-grace 三层保底")
    ap.add_argument("--no-doh-fill", action="store_true",
                    help="关闭「验证失败就用海外 DoH 现解析补位」")
    ap.add_argument("--ignore-upstream-ip", action="store_true",
                    help="忽略上游给的 IPv4，只把上游当域名清单（IPv4 全部用海外 DoH 现解析）")
    ap.add_argument("--geosite", default="",
                    help="改用 geosite 域名库（逗号分隔的类别，如 steam,epicgames,gog,github,category-games,"
                         "geolocation-!cn）；给了这个就不再读 sources.txt")
    ap.add_argument("--dry-run", action="store_true",
                    help="只汇总域名清单并打印统计，不做解析和探测")
    ap.add_argument("--doctor", action="store_true",
                    help="只体检解析器：可达性、延迟、是否返回污染地址，然后退出")
    ap.add_argument("--doh-near", default="",
                    help="替换近端 DoH（逗号分隔），例如香港/日本节点；留空用内置 hk-hkg + jp-kix")
    ap.add_argument("--doh-workers", type=int, default=40)
    ap.add_argument("--min-domains", type=int, default=500,
                    help="合并后域名少于该值时视为异常，直接放弃本次构建（不覆盖线上文件）")
    args = ap.parse_args()

    started = time.time()
    os.makedirs(args.out, exist_ok=True)
    if args.doh_near.strip():
        extra = [u.strip() for u in args.doh_near.split(",") if u.strip()]
        DOH_NEAR[:] = extra
        log(f"[doh] 近端解析器已替换为: {', '.join(extra)}")
    if args.doctor:
        return doctor()

    geosite_cats = [c.strip() for c in args.geosite.split(",") if c.strip()]
    if geosite_cats:
        # geosite 模式：不读 hosts 源，域名清单来自域名库，IP 全部靠 DoH 现解析
        doms, skipped, per_cat = load_geosite(geosite_cats)
        log(f"[geosite] 共 {len(doms)} 个域名（跳过 regexp/keyword/@cn {skipped} 条）")
        if args.dry_run:
            sample = sorted(doms)[:20]
            log("[dry-run] 前 20 个域名: " + ", ".join(sample))
            return 0
        if len(doms) < min(args.min_domains, 50) and not args.focus:
            log(f"[fatal] geosite 域名数 {len(doms)} 少于阈值，放弃本次构建")
            return 3
        cand = {d: {"4": {}, "6": {}} for d in doms}
        fetched = {}
        sources = []
        ok_sources = {"geosite"}
        failed_sources = set()
        per_source_stats = {"geosite": {"entries": len(doms), "cats": per_cat}}
    else:
        sources = read_sources(args.sources)
        log(f"[init] {len(sources)} 个源，输出目录 {args.out}")

        # 1) 抓取
        fetched = fetch_all(sources)
        ok_sources = {n for n, (t, txt, i) in fetched.items() if txt}
        failed_sources = {n for n in fetched if n not in ok_sources}
        if not ok_sources:
            log("[fatal] 所有源都抓取失败，保留上一版不动")
            return 2

        # 2) 解析
        cand = {}
        per_source_stats = {}
        for name, (tier, text, info) in fetched.items():
            if not text:
                per_source_stats[name] = {"entries": 0, "ok": False}
                continue
            parse_source(text, name, tier, cand, per_source_stats)

    log(f"[parse] 合并后域名 {len(cand)} 个")
    if not geosite_cats and len(cand) < args.min_domains and not args.focus:
        log(f"[fatal] 域名数 {len(cand)} < {args.min_domains}，疑似上游异常，放弃本次构建")
        return 3

    if args.ignore_upstream_ip:
        # 只把上游当域名清单：IPv4 全部交给海外 DoH 现解析（IPv6 仍沿用上游做交叉核对）
        for d in cand:
            cand[d]["4"] = {}
        log("[mode] ignore-upstream-ip：忽略上游 IPv4，全部现解析")

    # 3) 组装探测任务（把上一版的 IP 也当候选，用来判断它今天是否还活着）
    prev = load_prev(args.out)
    domains = sorted(cand)
    if args.focus:
        want = {x.strip().lower() for x in args.focus.split(",") if x.strip()}
        domains = [d for d in domains if d in want]
        log(f"[focus] 只处理 {len(domains)} 个指定域名")
    if args.limit:
        domains = domains[: args.limit]

    plan = {}
    for d in domains:
        slots = cand[d]["4"]
        if not slots:
            continue
        ordered = sorted(
            slots.items(),
            key=lambda kv: (kv[1]["tier"], -len(kv[1]["srcs"]), kv[0]),
        )[: args.max_probe]
        ips = [ip for ip, _ in ordered]
        old = prev.get(d, {}).get("v4")
        if old and old not in ips:
            ips.append(old)
        plan[d] = ips

    probe_tasks = [(d, ip) for d, ips in plan.items() for ip in ips]
    log(f"[probe] 待探测 IPv4 {len(probe_tasks)} 条（域名 {len(plan)} 个，并发 {args.concurrency}）")
    deadline = time.monotonic() + args.max_seconds
    t0 = time.time()
    results = asyncio.run(run_probes(probe_tasks, args.concurrency, args.timeout, deadline))
    log(f"[probe] TLS 探测完成 {len(results)} 条，用时 {time.time() - t0:.0f}s")

    # 3.5) TLS 没过的候选再补一次纯 TCP 探测：区分「IP 已死」和「只是 TLS 不通」
    need = [(d, ip) for (d, ip), (st, _) in results.items() if st != "ok"]
    if need:
        t1 = time.time()
        tcp_res = asyncio.run(
            run_probes(need, args.concurrency, min(args.timeout, 2.5), deadline, tps=TLS_PORT)
        )
        results.update(tcp_res)
        log(f"[probe] TCP 补测 {len(tcp_res)} 条，用时 {time.time() - t1:.0f}s")

    # 4) 选 IPv4
    chosen4, meta4 = {}, {}
    stats4 = {"verified": 0, "tier1-grace": 0, "carried": 0, "cert-mismatch": 0,
              "doh-resolved": 0, "critical-grace": 0, "dropped": 0}
    for d in domains:
        slots = cand[d]["4"]
        if not slots:
            continue
        ips = plan.get(d, [])

        def rank(ip, ms):
            s = slots.get(ip)
            return (s["tier"] if s else 9, -len(s["srcs"]) if s else 0, ms)

        alive = [(ip, results[(d, ip)][1]) for ip in ips
                 if results.get((d, ip), ("skip", 0))[0] == "ok"]
        if alive:
            alive.sort(key=lambda x: rank(*x))
            ip, ms = alive[0]
            chosen4[d] = ip
            meta4[d] = {"ip": ip, "ms": round(ms, 1), "status": "verified",
                        "srcs": sorted(slots.get(ip, {}).get("srcs", []))}
            stats4["verified"] += 1
            continue

        # 沿用上一版：前提是它今天 TCP 还连得上（死了就丢弃，避免把坏 IP 一直继承下去）
        old = prev.get(d, {}).get("v4")
        carry = int(prev.get(d, {}).get("carry4", 0))
        old_st = results.get((d, old), ("skip", 0))[0] if old else "skip"
        if old and old_st in ("ok", "tcp") and carry < CARRY_LIMIT:
            chosen4[d] = old
            meta4[d] = {"ip": old, "ms": None, "status": "carried",
                        "srcs": sorted(slots.get(old, {}).get("srcs", []))}
            stats4["carried"] += 1
            continue

        # 首次引导：tier1 精选源给的 IP，TCP 能通但 TLS 没完成（CDN 边缘/地区限制很常见）
        grace = []
        if not args.strict:
            for ip, s in slots.items():
                if s["tier"] != 1:
                    continue
                st = results.get((d, ip), ("skip", 0))[0]
                if st == "tcp":                  # 排除 "cert"：证书不对的绝不写
                    grace.append((ip, s))
        if grace:
            grace.sort(key=lambda kv: (-len(kv[1]["srcs"]), kv[0]))
            ip, s = grace[0]
            chosen4[d] = ip
            meta4[d] = {"ip": ip, "ms": None, "status": "tier1-grace",
                        "srcs": sorted(s["srcs"])}
            stats4["tier1-grace"] += 1
            continue

        if any(results.get((d, ip), ("skip", 0))[0] == "cert" for ip in ips):
            stats4["cert-mismatch"] += 1
        # 记录丢弃原因，方便跑完 Actions 后判断是「真死了」还是「只是探不通」
        sts = [results.get((d, ip), ("skip", 0))[0] for ip in ips]
        if "tcp" in sts:
            key = "drop_tcp_open_no_tls"      # IP 活着，但 TLS 没完成（多为探针侧网络问题）
        elif "cert" in sts:
            key = "drop_cert_mismatch"        # TLS 通了但证书不对（IP 已过期或不是这个站）
        elif "tcpfail" in sts:
            key = "drop_ip_unreachable"       # TCP 都连不上，IP 基本已死
        elif "timeout" in sts:
            key = "drop_timeout"              # 探测超时（预算用完或链路太慢）
        elif "fail" in sts:
            key = "drop_refused_reset"
        else:
            key = "drop_no_probe"
        stats4[key] = stats4.get(key, 0) + 1
        stats4["dropped"] += 1
    log(f"[select4] 保留 {len(chosen4)} 个域名  {stats4}")

    # 4.5) DoH 补位：上游 IP 全部验证失败的域名，用海外 DoH 现解析补上「此刻正确」的地址。
    #      这就是「其实只需要域名清单」的那条路——上游 IP 过期时不再白丢域名。
    #      只用 trusted 解析器，国内解析器对被墙域名会返回伪造地址。
    if not args.strict and not args.no_doh_fill:
        missing = [d for d in domains if d not in chosen4]
        if missing:
            t2 = time.time()
            log(f"[doh-fill] 为 {len(missing)} 个验证失败的域名做就近解析")
            near = doh_near_many(missing, workers=args.doh_workers)
            fill_src = {}          # domain -> ("near"|"global", [ips])
            need_global = []
            for d in missing:
                ips = [ip for ip in (near.get(d) or []) if usable_v4(ip)]
                # 已知污染 IP 排到最后，但**不直接丢弃**：它们会在证书复核里被淘汰，
                # 而多解析器合并后通常还有干净的候选可选。
                ordered = [ip for ip in ips if ip not in POISON_V4] + \
                          [ip for ip in ips if ip in POISON_V4]
                if ordered:
                    fill_src[d] = ("near", ordered[:4])
                else:
                    need_global.append(d)
            if need_global:
                g = doh_many(need_global, workers=args.doh_workers, rtype="A")
                for d, (ips, kind, _e) in g.items():
                    if kind != "trusted" or not ips:
                        continue
                    ok = [ip for ip in ips if usable_v4(ip) and ip not in POISON_V4]
                    if ok:
                        fill_src[d] = ("global", ok[:2])
            tasks = [(d, ip) for d, (_k, ips) in fill_src.items() for ip in ips]
            log(f"[doh-fill] 待证书复核 {len(tasks)} 条 / {len(fill_src)} 个域名")
            pr = asyncio.run(run_probes(tasks, args.concurrency, min(args.timeout, 2.5),
                                        time.monotonic() + 900))
            got_near = got_glob = 0
            for d, (kind, ips) in fill_src.items():
                good = [ip for ip in ips if pr.get((d, ip), ("", 0))[0] == "ok"]
                if not good:
                    continue
                st = "doh-near-verified" if kind == "near" else "doh-resolved"
                chosen4[d] = good[0]
                meta4[d] = {"ip": good[0], "ms": None, "status": st, "srcs": []}
                stats4[st] = stats4.get(st, 0) + 1
                if kind == "near":
                    got_near += 1
                else:
                    got_glob += 1
            log(f"[doh-fill] 就近解析通过 {got_near}，海外兜底通过 {got_glob}，用时 {time.time() - t2:.0f}s")

    # 4.6) 仍缺记录的关键域名：退一步用「TCP 能通」的源候选（绝不用连不上的地址）
    for d in domains:
        if d in chosen4 or d not in CRITICAL or not cand[d]["4"] or args.strict:
            continue
        tcp_ok = [(ip, s) for ip, s in cand[d]["4"].items()
                  if results.get((d, ip), ("skip", 0))[0] == "tcp"]
        if not tcp_ok:
            continue
        tcp_ok.sort(key=lambda kv: (kv[1]["tier"], -len(kv[1]["srcs"]), kv[0]))
        ip, s = tcp_ok[0]
        chosen4[d] = ip
        meta4[d] = {"ip": ip, "ms": None, "status": "critical-grace", "srcs": sorted(s["srcs"])}
        stats4["critical-grace"] = stats4.get("critical-grace", 0) + 1

    # 5) 选 IPv6（无法探测，用 DoH 交叉验证）
    if geosite_cats:
        # geosite 模式没有上游 v6 记录，全部靠 DoH 查 AAAA
        v6_hosts = sorted(set(domains) | (V6_ALWAYS if args.limit == 0 else set()))
    else:
        v6_hosts = sorted({d for d in domains if cand[d]["6"]} | (V6_ALWAYS & set(domains)) | (V6_ALWAYS if args.limit == 0 else set()))
    log(f"[doh] 校验 {len(v6_hosts)} 个域名的 AAAA")
    doh = doh_many(v6_hosts, workers=args.doh_workers)
    chosen6, meta6 = {}, {}
    v6_drop = v6_refresh = v6_match = v6_err = v6_unconfirmed = 0
    for d in v6_hosts:
        slots = cand.get(d, {"4": {}, "6": {}})["6"]
        current, kind, err = doh.get(d, (None, None, "missing"))
        if current is None:
            v6_err += 1
            old = prev.get(d, {}).get("v6")
            carry = int(prev.get(d, {}).get("carry6", 0))
            if old and carry < CARRY_LIMIT:
                chosen6[d] = old
                meta6[d] = {"ip": old, "status": "carried", "srcs": sorted(slots.get(old, {}).get("srcs", []))}
            continue
        cur = [ip for ip in current if usable_v6(ip) and not forged_v6(ip, d)]
        if not cur:
            v6_drop += 1          # 当前已无双栈记录（或只剩伪造地址）→ 上游是过期数据，丢弃
            continue
        old = prev.get(d, {}).get("v6")
        hit = [ip for ip in cur if ip in slots]
        if old and old in cur:
            chosen6[d] = old
            v6_match += 1
            meta6[d] = {"ip": old, "status": "verified",
                        "srcs": sorted(slots.get(old, {}).get("srcs", []))}
        elif hit:
            ip = hit[0]
            v6_match += 1
            meta6[d] = {"ip": ip, "status": "verified", "srcs": sorted(slots[ip]["srcs"])}
        elif kind == "trusted":
            # 只有海外解析器给出的、上游没记载的 AAAA 才允许作为新记录；
            # 国内解析器对被墙域名会返回伪造 AAAA（2001::1 / Facebook 段），绝不能采信
            ip = cur[0]
            v6_refresh += 1
            meta6[d] = {"ip": ip, "status": "doh-refreshed", "srcs": []}
        else:
            v6_unconfirmed += 1
            continue
        chosen6[d] = chosen6.get(d) or meta6[d]["ip"]
    log(f"[select6] 保留 {len(chosen6)}（命中上游 {v6_match}, 海外DoH刷新 {v6_refresh}, "
        f"丢弃过期 {v6_drop}, 无上游记录且只有国内解析器 {v6_unconfirmed}, DoH 失败 {v6_err}）")

    # DoH 整体不可达时的降级：IPv6 退回上游值（未校验），否则会一条 v6 都不剩。
    if v6_hosts and (len(v6_hosts) - v6_err) < max(1, len(v6_hosts) // 2):
        log("[warn] DoH 基本不可达，IPv6 退回上游值（status=upstream-unverified，未校验）")
        for d in v6_hosts:
            if d in chosen6:
                continue
            slots = cand.get(d, {"4": {}, "6": {}})["6"]
            if not slots:
                continue
            best = sorted(slots.items(), key=lambda kv: (kv[1]["tier"], -len(kv[1]["srcs"]), kv[0]))[0]
            chosen6[d] = best[0]
            meta6[d] = {"ip": best[0], "status": "upstream-unverified",
                        "srcs": sorted(best[1]["srcs"])}

    # v6 与 v4 保持「域名级一致」：IPv4 没活下来的域名，不单方面给它写一条 AAAA。
    # 否则客户端会优先走 IPv6，而这条 v6 我们并没有验证过路径可达，可能比没有记录更糟。
    # 例外是 V6_ALWAYS 里明确要保证的关键双栈域名。
    orphan = [d for d in chosen6 if d not in chosen4 and d not in V6_ALWAYS]
    for d in orphan:
        chosen6.pop(d, None)
        meta6.pop(d, None)
    if orphan:
        log(f"[select6] 因 IPv4 未存活而一并撤掉 AAAA 的域名 {len(orphan)} 个")

    # 6) 写文件
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if geosite_cats:
        src_note = "geosite: " + ",".join(geosite_cats)
        stats_extra = {"geosite_cats": geosite_cats}
    else:
        src_note = (f"sources-ok: {len(ok_sources)}/{len(sources)}  "
                    f"failed: {','.join(sorted(failed_sources)) or '-'}")
        stats_extra = {"sources_total": len(sources), "sources_ok": sorted(ok_sources),
                       "sources_failed": sorted(failed_sources)}
    lines = [
        "# hosts-aggregator build",
        f"# generated: {stamp}",
        f"# {src_note}",
        f"# domains: {len(set(chosen4) | set(chosen6))}  ipv4: {len(chosen4)}  ipv6: {len(chosen6)}",
        "# policy: IPv4 = TLS(SNI+cert) verified; IPv6 = DoH cross-checked (CI 无 IPv6 出口，无法直连验证)",
        "# one IPv4 + one IPv6 per domain on purpose (多写几条会让客户端死等坏 IP)",
        "",
    ]
    for d in sorted(set(chosen4) | set(chosen6)):
        if d in chosen4:
            lines.append(f"{chosen4[d]}\t{d}")
        if d in chosen6:
            lines.append(f"{chosen6[d]}\t{d}")
    hosts_path = os.path.join(args.out, "hosts.txt")
    with open(hosts_path, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines) + "\n")

    # 7) 审计表
    csv_path = os.path.join(args.out, "selected.csv")
    with open(csv_path, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["domain", "ip4", "status4", "ms4", "src4", "ip6", "status6", "src6"])
        for d in sorted(set(chosen4) | set(chosen6)):
            m4 = meta4.get(d, {})
            m6 = meta6.get(d, {})
            w.writerow([
                d, m4.get("ip", ""), m4.get("status") or "-", m4.get("ms", ""),
                ";".join(m4.get("srcs", [])),
                m6.get("ip", ""), m6.get("status") or "-", ";".join(m6.get("srcs", [])),
            ])

    # 8) 状态与上一版快照
    stats = {
        "generated": stamp,
        **stats_extra,
        "domains": len(set(chosen4) | set(chosen6)),
        "ipv4": len(chosen4),
        "ipv6": len(chosen6),
        "status4": _count([m["status"] for m in meta4.values()]),
        "v4_detail": stats4,
        "status6": _count([m["status"] for m in meta6.values()]),
        "v6_detail": {
            "matched_upstream": v6_match,
            "refreshed_by_trusted_doh": v6_refresh,
            "dropped_stale": v6_drop,
            "unconfirmed_cn_only": v6_unconfirmed,
            "doh_failed": v6_err,
        },
        "per_source_entries": per_source_stats,
        "elapsed_sec": round(time.time() - started, 1),
    }
    with open(os.path.join(args.out, "stats.json"), "w", encoding="utf-8") as f:
        json.dump(stats, f, ensure_ascii=False, indent=2)

    prev_next = {}
    for d in set(chosen4) | set(chosen6):
        s4 = meta4.get(d, {}).get("status")
        prev_next[d] = {
            "v4": chosen4.get(d),
            "v6": chosen6.get(d),
            # verified / tier1-grace 都算「这次有正面信号」，重置失败计数
            "carry4": 0 if s4 in ("verified", "tier1-grace") else int(prev.get(d, {}).get("carry4", 0)) + 1,
            "carry6": 0 if meta6.get(d, {}).get("status") in ("verified", "doh-refreshed") else int(prev.get(d, {}).get("carry6", 0)) + 1,
        }
    with open(os.path.join(args.out, "prev.json"), "w", encoding="utf-8") as f:
        json.dump(prev_next, f, ensure_ascii=False, separators=(",", ":"))

    log(f"[done] {stats['domains']} 域名 / v4 {stats['ipv4']} / v6 {stats['ipv6']} / {stats['elapsed_sec']}s -> {hosts_path}")
    return 0


def _count(items):
    out = {}
    for i in items:
        out[i] = out.get(i, 0) + 1
    return out


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
