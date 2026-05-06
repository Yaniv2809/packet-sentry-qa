from scapy.all import rdpcap, conf
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dns import DNS
from scapy.packet import Raw

conf.verb = 0


def load_pcap(path: str) -> list:
    return list(rdpcap(path))


def get_tcp_packets(packets: list) -> list:
    return [p for p in packets if IP in p and TCP in p]


def get_dns_packets(packets: list) -> list:
    return [p for p in packets if DNS in p]


def get_sip_packets(packets: list) -> list:
    return [
        p for p in packets
        if UDP in p and Raw in p and (p[UDP].sport == 5060 or p[UDP].dport == 5060)
    ]
