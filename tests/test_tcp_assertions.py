import pytest
import allure
from engines.pcap_parser import load_pcap
from engines.assertions import assert_tcp_handshake_latency
from engines.reporter import build_report, to_json, build_wireshark_filter


@pytest.mark.tcp
@allure.epic("PCAP Protocol Assertions")
@allure.feature("Layer 4 - TCP")
@allure.story("Handshake Latency")
class TestTCPAssertions:

    @allure.title("Detect TCP Handshake Exceeding 200ms Threshold")
    @allure.description("Verifies the engine flags the slow SYN→SYN-ACK session (250ms) and ignores the fast one (50ms).")
    @allure.severity(allure.severity_level.CRITICAL)
    def test_slow_handshake_detected(self, tcp_pcap):
        packets = load_pcap(tcp_pcap)
        result = assert_tcp_handshake_latency(packets, max_ms=200)

        assert result["passed"] is False
        assert len(result["failures"]) == 1
        assert result["failures"][0]["latency_ms"] > 200
        assert result["failures"][0]["src_ip"] == "10.0.0.3"

    @allure.title("Fast TCP Handshake (50ms) Is Not Flagged")
    @allure.severity(allure.severity_level.NORMAL)
    def test_fast_handshake_not_flagged(self, tcp_pcap):
        packets = load_pcap(tcp_pcap)
        result = assert_tcp_handshake_latency(packets, max_ms=200)

        flagged_srcs = [f["src_ip"] for f in result["failures"]]
        assert "10.0.0.1" not in flagged_srcs

    @allure.title("Custom Threshold: Both Handshakes Fail at 10ms")
    @allure.description("Confirms the threshold is configurable — at 10ms both sessions should be flagged.")
    @allure.severity(allure.severity_level.NORMAL)
    def test_custom_threshold_flags_both(self, tcp_pcap):
        packets = load_pcap(tcp_pcap)
        result = assert_tcp_handshake_latency(packets, max_ms=10)

        assert result["passed"] is False
        assert len(result["failures"]) == 2

    @allure.title("Wireshark Filter Targets the Slow Session")
    @allure.severity(allure.severity_level.NORMAL)
    def test_wireshark_filter_targets_slow_session(self, tcp_pcap):
        packets = load_pcap(tcp_pcap)
        result = assert_tcp_handshake_latency(packets, max_ms=200)
        ws_filter = build_wireshark_filter([result])

        assert "10.0.0.3" in ws_filter
        allure.attach(ws_filter, name="Wireshark Filter", attachment_type=allure.attachment_type.TEXT)

    @allure.title("JSON Report Contains Latency Value")
    @allure.severity(allure.severity_level.NORMAL)
    def test_json_report_contains_latency(self, tcp_pcap):
        packets = load_pcap(tcp_pcap)
        result = assert_tcp_handshake_latency(packets, max_ms=200)
        report = build_report([result])

        assert report["summary"]["failed"] == 1
        failure = report["results"][0]["failures"][0]
        assert "latency_ms" in failure
        allure.attach(to_json(report), name="JSON Report", attachment_type=allure.attachment_type.TEXT)
