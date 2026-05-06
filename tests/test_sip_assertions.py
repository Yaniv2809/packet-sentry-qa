import pytest
import allure
from engines.pcap_parser import load_pcap
from engines.assertions import assert_sip_calls_completed
from engines.reporter import build_report, to_json, build_wireshark_filter


@pytest.mark.sip
@allure.epic("PCAP Protocol Assertions")
@allure.feature("Layer 7 - SIP/VoIP")
@allure.story("Call Completion")
class TestSIPAssertions:

    @allure.title("Detect SIP INVITE Without 200 OK")
    @allure.description("Verifies that an INVITE with only 180 Ringing and no 200 OK is flagged as an incomplete call.")
    @allure.severity(allure.severity_level.BLOCKER)
    def test_incomplete_call_detected(self, sip_pcap):
        packets = load_pcap(sip_pcap)
        result = assert_sip_calls_completed(packets)

        assert result["passed"] is False
        assert len(result["failures"]) == 1
        assert result["failures"][0]["call_id"] == "call-bbb222"
        assert result["failures"][0]["type"] == "sip_call_not_completed"

    @allure.title("Complete SIP Call (INVITE + 200 OK) Is Not Flagged")
    @allure.severity(allure.severity_level.NORMAL)
    def test_complete_call_not_flagged(self, sip_pcap):
        packets = load_pcap(sip_pcap)
        result = assert_sip_calls_completed(packets)

        flagged_ids = [f["call_id"] for f in result["failures"]]
        assert "call-aaa111" not in flagged_ids

    @allure.title("Wireshark Filter Identifies the Incomplete Call by Call-ID")
    @allure.severity(allure.severity_level.NORMAL)
    def test_wireshark_filter_for_failed_call(self, sip_pcap):
        packets = load_pcap(sip_pcap)
        result = assert_sip_calls_completed(packets)
        ws_filter = build_wireshark_filter([result])

        assert "call-bbb222" in ws_filter
        assert "call-aaa111" not in ws_filter
        allure.attach(ws_filter, name="Wireshark Filter", attachment_type=allure.attachment_type.TEXT)

    @allure.title("JSON Report Exposes Call-ID in Failure Details")
    @allure.severity(allure.severity_level.NORMAL)
    def test_json_report_exposes_call_id(self, sip_pcap):
        packets = load_pcap(sip_pcap)
        result = assert_sip_calls_completed(packets)
        report = build_report([result])

        assert report["summary"]["failed"] == 1
        failure = report["results"][0]["failures"][0]
        assert failure["call_id"] == "call-bbb222"
        allure.attach(to_json(report), name="JSON Report", attachment_type=allure.attachment_type.TEXT)
