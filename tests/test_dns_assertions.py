import pytest
import allure
from engines.pcap_parser import load_pcap
from engines.assertions import assert_no_dns_nxdomain
from engines.reporter import build_report, to_json, build_wireshark_filter


@pytest.mark.dns
@allure.epic("PCAP Protocol Assertions")
@allure.feature("Layer 7 - DNS")
@allure.story("NXDOMAIN Detection")
class TestDNSAssertions:

    @allure.title("Detect DNS NXDOMAIN Response in PCAP")
    @allure.description("Verifies the assertion engine flags RCODE=3 (NXDOMAIN) responses and leaves valid resolutions untouched.")
    @allure.severity(allure.severity_level.CRITICAL)
    def test_nxdomain_detected(self, dns_pcap):
        packets = load_pcap(dns_pcap)
        result = assert_no_dns_nxdomain(packets)

        assert result["passed"] is False
        assert len(result["failures"]) == 1
        assert result["failures"][0]["type"] == "dns_nxdomain"
        assert "nonexistent.badhost.local" in result["failures"][0]["query"]

    @allure.title("Successful DNS Resolution Is Not Flagged")
    @allure.severity(allure.severity_level.NORMAL)
    def test_valid_resolution_not_flagged(self, dns_pcap):
        packets = load_pcap(dns_pcap)
        result = assert_no_dns_nxdomain(packets)

        flagged_queries = [f["query"] for f in result["failures"]]
        assert "checkpoint.com" not in flagged_queries

    @allure.title("Wireshark Filter References the Failed Domain")
    @allure.severity(allure.severity_level.NORMAL)
    def test_wireshark_filter_output(self, dns_pcap):
        packets = load_pcap(dns_pcap)
        result = assert_no_dns_nxdomain(packets)
        ws_filter = build_wireshark_filter([result])

        assert "nonexistent.badhost.local" in ws_filter
        allure.attach(ws_filter, name="Wireshark Filter", attachment_type=allure.attachment_type.TEXT)

    @allure.title("JSON Report Contains Correct Failure Summary")
    @allure.severity(allure.severity_level.NORMAL)
    def test_json_report_structure(self, dns_pcap):
        packets = load_pcap(dns_pcap)
        result = assert_no_dns_nxdomain(packets)
        report = build_report([result])

        assert report["summary"]["total_assertions"] == 1
        assert report["summary"]["failed"] == 1
        assert report["summary"]["passed"] == 0
        allure.attach(to_json(report), name="JSON Report", attachment_type=allure.attachment_type.TEXT)
