import unittest
from engine.orchestrator import SOAROrchestrator
from engine.integrations.threat_intel import ThreatIntelService
from engine.integrations.firewall import FirewallService
from engine.integrations.identity import IdentityService
from engine.integrations.ticketing import CaseManagementService
from engine.integrations.notifier import NotificationService

class TestSOAREngine(unittest.TestCase):
    def setUp(self):
        self.config = {
            "thresholds": {
                "phishing_malicious_engines": 3,
                "abuseipdb_confidence_score": 75,
                "brute_force_failed_attempts": 5
            },
            "integrations": {
                "virustotal": {"api_key": ""},
                "abuseipdb": {"api_key": ""},
                "slack": {"webhook_url": "https://hooks.slack.com/services/MOCK"},
                "firewall": {"driver": "mock_iptables"},
                "identity": {"driver": "mock_okta"}
            }
        }
        self.orchestrator = SOAROrchestrator(config=self.config)

    def test_phishing_malicious_containment(self):
        alert = {
            "recipient_email": "target@apexfin.corp",
            "sender_email": "attacker@login-microsoft-verify.top",
            "sender_ip": "185.220.101.5",
            "extracted_urls": ["https://login-microsoft-verify.top/login"]
        }
        res = self.orchestrator.run_playbook("phishing_triage", alert)
        self.assertEqual(res["status"], "SUCCESS")
        self.assertEqual(res["verdict"], "MALICIOUS_CONTAINED")
        self.assertIsNotNone(res["case_id"])
        self.assertTrue(any("Revoked active" in a for a in res["actions_taken"]))
        self.assertTrue(any("Sinkholed sender domain" in a for a in res["actions_taken"]))

    def test_phishing_benign_cleared(self):
        alert = {
            "recipient_email": "target@apexfin.corp",
            "sender_email": "newsletter@partner-bank.com",
            "sender_ip": "54.240.8.10",
            "extracted_urls": ["https://partner-bank.com/q3-report"]
        }
        res = self.orchestrator.run_playbook("phishing_triage", alert)
        self.assertEqual(res["status"], "SUCCESS")
        self.assertEqual(res["verdict"], "BENIGN_CLEARED")
        self.assertIsNone(res["case_id"])

    def test_bruteforce_containment_threshold(self):
        alert = {
            "attacker_ip": "194.26.29.66",
            "attempt_count": 10,
            "service": "SSH Service"
        }
        res = self.orchestrator.run_playbook("bruteforce_containment", alert)
        self.assertEqual(res["status"], "SUCCESS")
        self.assertEqual(res["verdict"], "ATTACKER_CONTAINED")
        self.assertIsNotNone(res["case_id"])
        self.assertTrue(any("iptables DROP" in a for a in res["actions_taken"]))

    def test_threat_intel_ip_private(self):
        intel = ThreatIntelService()
        res = intel.inspect_ip("192.168.1.50")
        self.assertEqual(res["verdict"], "BENIGN")
        self.assertEqual(res["country"], "LAN/Internal")

        res_loopback = intel.inspect_ip("127.0.0.1")
        self.assertEqual(res_loopback["verdict"], "BENIGN")

    def test_threat_intel_url_empty(self):
        intel = ThreatIntelService()
        res = intel.inspect_url("")
        self.assertEqual(res["verdict"], "BENIGN")

    def test_threat_intel_hash_empty(self):
        intel = ThreatIntelService()
        res = intel.inspect_hash("")
        self.assertEqual(res["verdict"], "BENIGN")
        self.assertIsNone(res["family"])

    def test_unknown_playbook_handled(self):
        res = self.orchestrator.run_playbook("non_existent_playbook", {})
        self.assertEqual(res["status"], "FAILED")
        self.assertEqual(res["verdict"], "EXECUTION_ERROR")

if __name__ == "__main__":
    unittest.main()
