from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dns import DNS, DNSQR
from scapy.packet import Raw

_SYN     = 0x02
_ACK     = 0x10
_SYN_ACK = 0x12


def assert_no_dns_nxdomain(packets: list) -> dict:
    failures = []

    for pkt in packets:
        if DNS not in pkt:
            continue
        dns = pkt[DNS]
        if dns.qr == 1 and dns.rcode == 3:
            query = (
                dns.qd.qname.decode("utf-8", errors="ignore").rstrip(".")
                if dns.qd else "unknown"
            )
            failures.append({
                "type": "dns_nxdomain",
                "query": query,
                "src_ip": pkt[IP].src if IP in pkt else "unknown",
                "dst_ip": pkt[IP].dst if IP in pkt else "unknown",
                "wireshark_filter": f'dns.qry.name=="{query}"',
            })

    return {
        "assertion": "no_dns_nxdomain",
        "passed": len(failures) == 0,
        "failures": failures,
    }


def assert_tcp_handshake_latency(packets: list, max_ms: float = 200) -> dict:
    syns = {}
    failures = []

    for pkt in packets:
        if IP not in pkt or TCP not in pkt:
            continue
        ip, tcp = pkt[IP], pkt[TCP]
        flags = int(tcp.flags)

        if flags == _SYN:
            key = (ip.src, tcp.sport, ip.dst, tcp.dport)
            syns[key] = float(pkt.time)

        elif flags == _SYN_ACK:
            key = (ip.dst, tcp.dport, ip.src, tcp.sport)
            if key in syns:
                latency_ms = (float(pkt.time) - syns[key]) * 1000
                if latency_ms > max_ms:
                    failures.append({
                        "type": "tcp_slow_handshake",
                        "src_ip": key[0],
                        "src_port": key[1],
                        "dst_ip": key[2],
                        "dst_port": key[3],
                        "latency_ms": round(latency_ms, 2),
                        "threshold_ms": max_ms,
                        "wireshark_filter": (
                            f"(ip.src=={key[0]} && tcp.srcport=={key[1]}"
                            f" && ip.dst=={key[2]} && tcp.dstport=={key[3]})"
                        ),
                    })

    return {
        "assertion": "tcp_handshake_latency",
        "passed": len(failures) == 0,
        "failures": failures,
    }


def assert_sip_calls_completed(packets: list) -> dict:
    invites: dict = {}
    ok_responses: set = set()

    for pkt in packets:
        if UDP not in pkt or Raw not in pkt:
            continue
        payload = pkt[Raw].load.decode("utf-8", errors="ignore")
        call_id = _extract_sip_header(payload, "call-id")
        if not call_id:
            continue

        if payload.startswith("INVITE"):
            invites[call_id] = pkt
        elif payload.startswith("SIP/2.0 200"):
            ok_responses.add(call_id)

    failures = []
    for call_id, pkt in invites.items():
        if call_id not in ok_responses:
            failures.append({
                "type": "sip_call_not_completed",
                "call_id": call_id,
                "src_ip": pkt[IP].src if IP in pkt else "unknown",
                "dst_ip": pkt[IP].dst if IP in pkt else "unknown",
                "wireshark_filter": f'sip.Call-ID=="{call_id}"',
            })

    return {
        "assertion": "sip_calls_completed",
        "passed": len(failures) == 0,
        "failures": failures,
    }


def _extract_sip_header(payload: str, header_name: str) -> str | None:
    for line in payload.split("\r\n"):
        if line.lower().startswith(f"{header_name}:"):
            return line.split(":", 1)[1].strip()
    return None
