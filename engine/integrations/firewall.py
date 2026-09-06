import logging
from typing import Dict, Any, List

logger = logging.getLogger("soar.firewall")

class FirewallService:
    def __init__(self, driver: str = "mock_iptables"):
        self.driver = driver
        self.blocked_ips: List[Dict[str, Any]] = []
        self.blocked_domains: List[Dict[str, Any]] = []

    def block_ip(self, ip_address: str, reason: str, ttl_minutes: int = 1440) -> Dict[str, Any]:
        """
        Injects an ingress DROP rule on perimeter firewalls.
        """
        rule = {
            "ip": ip_address,
            "rule": f"iptables -I INPUT -s {ip_address} -j DROP",
            "reason": reason,
            "ttl_minutes": ttl_minutes,
            "applied_at": "ACTIVE"
        }
        self.blocked_ips.append(rule)
        logger.info(f"[Firewall] Blocked IP {ip_address}. Rule: {rule['rule']}")
        return {
            "status": "success",
            "action": "FIREWALL_RULE_APPLIED",
            "ip": ip_address,
            "driver": self.driver,
            "rule": rule["rule"]
        }

    def block_domain(self, domain: str, reason: str) -> Dict[str, Any]:
        """
        Adds malicious domain to DNS sinkhole / web proxy blocklist.
        """
        entry = {"domain": domain, "reason": reason}
        self.blocked_domains.append(entry)
        logger.info(f"[DNS/WAF] Sinkholed domain: {domain}")
        return {
            "status": "success",
            "action": "DOMAIN_SINKHOLED",
            "domain": domain,
            "driver": self.driver
        }
