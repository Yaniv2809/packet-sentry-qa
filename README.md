# PacketSentry

**PCAP Analyzer & Protocol Assertions Library**

PacketSentry is a Python framework for running programmatic assertions against network traffic captures. Instead of opening Wireshark and eyeballing packets, you define pass/fail rules — and the engine tells you exactly what violated them, plus a ready-to-paste Wireshark filter to jump straight to the evidence.

Built with [Scapy](https://scapy.net/) and pytest. Zero external tools required.

---

## What It Does

Given a `.pcap` file, PacketSentry runs a suite of protocol assertions:

| Assertion | Protocol | Layer | Flags a failure when... |
|---|---|---|---|
| `assert_no_dns_nxdomain` | DNS | L7 | Any response carries `RCODE=3` (NXDOMAIN) |
| `assert_tcp_handshake_latency` | TCP | L4 | SYN → SYN-ACK round-trip exceeds the threshold (default: 200ms) |
| `assert_sip_calls_completed` | SIP | L7 | An `INVITE` has no matching `200 OK` (call never connected) |

Every failure produces:
- A structured entry in the **JSON report** (type, IPs, protocol details)
- A **Wireshark display filter string** targeting the exact offending packets

---

## Architecture

```
PacketSentry/
├── engines/
│   ├── pcap_parser.py      # load_pcap() + per-protocol packet filters
│   ├── assertions.py       # the three assertion functions
│   └── reporter.py         # JSON report builder + Wireshark filter generator
└── tests/
    ├── conftest.py          # synthetic .pcap fixtures (Scapy packet crafting)
    ├── test_dns_assertions.py
    ├── test_tcp_assertions.py
    └── test_sip_assertions.py
```

### Layer responsibilities

**`pcap_parser.py`** — I/O only. Loads a `.pcap` file into a list of Scapy packet objects and exposes filter helpers (`get_dns_packets`, `get_tcp_packets`, `get_sip_packets`).

**`assertions.py`** — Pure logic. Each function receives a packet list, applies its rule, and returns a result dict with `passed`, `failures`, and per-failure `wireshark_filter` strings. No file I/O, no side effects.

**`reporter.py`** — Output only. Accepts a list of assertion results and produces either a JSON report or a combined Wireshark filter string.

This separation means assertions can be composed freely — run one, run all, combine filters across protocols.

---

## Synthetic PCAP Generation

The test suite does not ship with `.pcap` sample files. Instead, `conftest.py` uses Scapy to **craft packets from scratch** at test time, write them to a temporary file, and let pytest clean up on teardown.

This approach solves three problems at once:

1. **Self-contained** — `git clone` + `pip install` is all that's needed. No external files to manage.
2. **Deterministic** — each fixture constructs exactly the scenario under test. The slow TCP handshake is precisely 250ms because `pkt.time` is set that way. No flakiness from real-world traffic variability.
3. **Negative-path coverage** — crafting a "broken" scenario (an INVITE with no 200 OK, a DNS response with `rcode=3`) would take minutes to find in the wild. Here it's three lines of code.

### Example: crafting a slow TCP handshake

```python
syn = IP(src="10.0.0.3", dst="10.0.0.2") / TCP(sport=2002, dport=443, flags="S", seq=3000)
syn.time = 1.00                  # timestamp injected into the pcap

synack = IP(src="10.0.0.2", dst="10.0.0.3") / TCP(sport=443, dport=2002, flags="SA", ack=3001)
synack.time = 1.25               # 250ms later — exceeds the 200ms threshold

wrpcap(str(path), [syn, synack, ...])
```

The assertion then reads `pkt.time` from the loaded pcap, computes the delta, and flags this session.

---

## Quick Start

```bash
git clone https://github.com/your-username/PacketSentry.git
cd PacketSentry

python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

pip install -r requirements.txt
```

---

## Running Tests

**Full suite:**
```bash
pytest tests/ -v
```

**By protocol layer:**
```bash
pytest tests/ -m dns
pytest tests/ -m tcp
pytest tests/ -m sip
```

**With Allure report:**
```bash
pytest tests/ -v --alluredir=allure-results
allure serve allure-results
```

---

## Using the Assertions Against Your Own PCAPs

The engines are importable independently of pytest:

```python
from engines.pcap_parser import load_pcap
from engines.assertions import assert_no_dns_nxdomain, assert_tcp_handshake_latency, assert_sip_calls_completed
from engines.reporter import build_report, to_json, build_wireshark_filter

packets = load_pcap("capture.pcap")

results = [
    assert_no_dns_nxdomain(packets),
    assert_tcp_handshake_latency(packets, max_ms=150),
    assert_sip_calls_completed(packets),
]

report = build_report(results)
print(to_json(report))
print(build_wireshark_filter(results))
```

---

## Output Examples

### JSON report

```json
{
  "generated_at": "2026-05-06T10:00:00+00:00",
  "summary": {
    "total_assertions": 3,
    "passed": 2,
    "failed": 1
  },
  "results": [
    {
      "assertion": "tcp_handshake_latency",
      "passed": false,
      "failures": [
        {
          "type": "tcp_slow_handshake",
          "src_ip": "10.0.0.3",
          "src_port": 2002,
          "dst_ip": "10.0.0.2",
          "dst_port": 443,
          "latency_ms": 250.0,
          "threshold_ms": 200,
          "wireshark_filter": "(ip.src==10.0.0.3 && tcp.srcport==2002 && ip.dst==10.0.0.2 && tcp.dstport==443)"
        }
      ]
    }
  ]
}
```

### Wireshark filter string

```
(ip.src==10.0.0.3 && tcp.srcport==2002 && ip.dst==10.0.0.2 && tcp.dstport==443) || dns.qry.name=="nonexistent.badhost.local"
```

Copy, paste into Wireshark's display filter bar — the exact offending packets are isolated immediately.

---

## Test Coverage

13 tests across 3 protocol layers:

| File | Tests | What they verify |
|---|---|---|
| `test_dns_assertions.py` | 4 | NXDOMAIN detected, valid resolution not flagged, Wireshark filter content, JSON report structure |
| `test_tcp_assertions.py` | 5 | Slow session detected, fast session not flagged, configurable threshold, Wireshark filter targets correct IP, JSON contains latency value |
| `test_sip_assertions.py` | 4 | Incomplete call detected by Call-ID, complete call not flagged, Wireshark filter isolates failed call, JSON exposes Call-ID |

---

## CI/CD

GitHub Actions runs the full suite on every push and pull request. Allure results are uploaded as a build artifact.

See `.github/workflows/ci.yml`.

---

## Requirements

- Python 3.10+
- Scapy 2.7.0
- No WinPcap / Npcap required — file-based pcap I/O only
