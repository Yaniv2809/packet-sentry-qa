import pytest
from scapy.all import wrpcap, conf
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.packet import Raw

conf.verb = 0


@pytest.fixture
def dns_pcap(tmp_path):
    q_ok = IP(src="192.168.1.10", dst="8.8.8.8") / UDP(sport=12345, dport=53) / \
           DNS(id=1, rd=1, qd=DNSQR(qname="checkpoint.com"))
    q_ok.time = 0.0

    r_ok = IP(src="8.8.8.8", dst="192.168.1.10") / UDP(sport=53, dport=12345) / \
           DNS(id=1, qr=1, aa=1, rcode=0, qdcount=1, ancount=1,
               qd=DNSQR(qname="checkpoint.com"),
               an=DNSRR(rrname="checkpoint.com", type="A", rdata="216.0.0.1"))
    r_ok.time = 0.01

    q_nx = IP(src="192.168.1.10", dst="8.8.8.8") / UDP(sport=12346, dport=53) / \
           DNS(id=2, rd=1, qd=DNSQR(qname="nonexistent.badhost.local"))
    q_nx.time = 0.10

    r_nx = IP(src="8.8.8.8", dst="192.168.1.10") / UDP(sport=53, dport=12346) / \
           DNS(id=2, qr=1, rcode=3, qdcount=1, ancount=0,
               qd=DNSQR(qname="nonexistent.badhost.local"))
    r_nx.time = 0.11

    path = tmp_path / "dns_test.pcap"
    wrpcap(str(path), [q_ok, r_ok, q_nx, r_nx])
    yield str(path)


@pytest.fixture
def tcp_pcap(tmp_path):
    # Fast handshake: 50 ms  →  PASS
    syn1 = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1001, dport=443, flags="S", seq=1000)
    syn1.time = 0.0
    synack1 = IP(src="10.0.0.2", dst="10.0.0.1") / TCP(sport=443, dport=1001, flags="SA", seq=2000, ack=1001)
    synack1.time = 0.05
    ack1 = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1001, dport=443, flags="A", seq=1001, ack=2001)
    ack1.time = 0.06

    # Slow handshake: 250 ms  →  FAIL
    syn2 = IP(src="10.0.0.3", dst="10.0.0.2") / TCP(sport=2002, dport=443, flags="S", seq=3000)
    syn2.time = 1.00
    synack2 = IP(src="10.0.0.2", dst="10.0.0.3") / TCP(sport=443, dport=2002, flags="SA", seq=4000, ack=3001)
    synack2.time = 1.25
    ack2 = IP(src="10.0.0.3", dst="10.0.0.2") / TCP(sport=2002, dport=443, flags="A", seq=3001, ack=4001)
    ack2.time = 1.26

    path = tmp_path / "tcp_test.pcap"
    wrpcap(str(path), [syn1, synack1, ack1, syn2, synack2, ack2])
    yield str(path)


@pytest.fixture
def sip_pcap(tmp_path):
    # Complete call: INVITE → 180 Ringing → 200 OK  →  PASS
    invite1 = IP(src="10.1.0.1", dst="10.1.0.2") / UDP(sport=5060, dport=5060) / \
              Raw(load=b"INVITE sip:bob@example.com SIP/2.0\r\nCall-ID: call-aaa111\r\nCSeq: 1 INVITE\r\n\r\n")
    invite1.time = 0.0

    ringing1 = IP(src="10.1.0.2", dst="10.1.0.1") / UDP(sport=5060, dport=5060) / \
               Raw(load=b"SIP/2.0 180 Ringing\r\nCall-ID: call-aaa111\r\n\r\n")
    ringing1.time = 0.1

    ok1 = IP(src="10.1.0.2", dst="10.1.0.1") / UDP(sport=5060, dport=5060) / \
          Raw(load=b"SIP/2.0 200 OK\r\nCall-ID: call-aaa111\r\n\r\n")
    ok1.time = 3.5

    # Incomplete call: INVITE → 180 Ringing, no 200 OK  →  FAIL
    invite2 = IP(src="10.1.0.3", dst="10.1.0.2") / UDP(sport=5060, dport=5060) / \
              Raw(load=b"INVITE sip:charlie@example.com SIP/2.0\r\nCall-ID: call-bbb222\r\nCSeq: 1 INVITE\r\n\r\n")
    invite2.time = 5.0

    ringing2 = IP(src="10.1.0.2", dst="10.1.0.3") / UDP(sport=5060, dport=5060) / \
               Raw(load=b"SIP/2.0 180 Ringing\r\nCall-ID: call-bbb222\r\n\r\n")
    ringing2.time = 5.1

    path = tmp_path / "sip_test.pcap"
    wrpcap(str(path), [invite1, ringing1, ok1, invite2, ringing2])
    yield str(path)
