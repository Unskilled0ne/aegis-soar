import json
import os
from typing import Dict, Any, List, Optional
from engine.models import SecurityAlert, EnrichmentContext, UserContext, AssetContext
from engine.integrations.threat_intel import ThreatIntelService

class EnrichmentPipeline:
    def __init__(self, threat_intel: ThreatIntelService, config: Optional[Dict[str, Any]] = None):
        self.threat_intel = threat_intel
        self.config = config or {}
        
        self.user_directory = {
            "v.tsiamouras@apexfin.corp": UserContext(
                username="v.tsiamouras",
                email="v.tsiamouras@apexfin.corp",
                department="Security Engineering",
                role="Senior SOC Engineer",
                is_vip=False,
                mfa_enabled=True,
                account_status="ACTIVE"
            ),
            "ceo@apexfin.corp": UserContext(
                username="alex.carter",
                email="ceo@apexfin.corp",
                department="Executive Leadership",
                role="Chief Executive Officer",
                is_vip=True,
                mfa_enabled=True,
                account_status="ACTIVE"
            ),
            "finance.ops@apexfin.corp": UserContext(
                username="finance.ops",
                email="finance.ops@apexfin.corp",
                department="Treasury",
                role="Payment Processor",
                is_vip=False,
                mfa_enabled=True,
                account_status="ACTIVE"
            )
        }

        self.asset_inventory = {
            "192.168.1.150": AssetContext(
                hostname="prod-ssh-bastion",
                ip_address="192.168.1.150",
                asset_criticality="HIGH",
                environment="production",
                os="Linux Ubuntu 22.04 LTS",
                owner="Infrastructure"
            ),
            "10.0.4.12": AssetContext(
                hostname="core-ledger-db-01",
                ip_address="10.0.4.12",
                asset_criticality="CRITICAL",
                environment="production",
                os="Linux Debian 12",
                owner="Database Team"
            ),
            "185.220.101.5": AssetContext(
                hostname="ext-mail-gateway",
                ip_address="185.220.101.5",
                asset_criticality="MEDIUM",
                environment="corporate",
                os="Alpine Linux",
                owner="Network Operations"
            )
        }

    def enrich(self, alert: SecurityAlert) -> EnrichmentContext:
        threat_data: Dict[str, Any] = {}

        if alert.source_ip:
            threat_data[f"ip:{alert.source_ip}"] = self.threat_intel.inspect_ip(alert.source_ip)

        for url in alert.extracted_urls:
            threat_data[f"url:{url}"] = self.threat_intel.inspect_url(url)

        for file_hash in alert.file_hashes:
            threat_data[f"hash:{file_hash}"] = self.threat_intel.inspect_hash(file_hash)

        user_ctx = None
        if alert.user_identity:
            user_ctx = self.user_directory.get(alert.user_identity.lower())
            if not user_ctx and "@" in alert.user_identity:
                username = alert.user_identity.split("@")[0]
                user_ctx = UserContext(
                    username=username,
                    email=alert.user_identity,
                    department="General Staff",
                    role="Employee"
                )

        asset_ctx = None
        target_ip = alert.destination_ip or alert.source_ip
        if target_ip and target_ip in self.asset_inventory:
            asset_ctx = self.asset_inventory[target_ip]
        elif alert.target_host:
            for asset in self.asset_inventory.values():
                if asset.hostname.lower() == alert.target_host.lower():
                    asset_ctx = asset
                    break

        correlated = self._find_correlated_events(alert)

        return EnrichmentContext(
            alert_id=alert.alert_id,
            threat_intel=threat_data,
            user_context=user_ctx,
            asset_context=asset_ctx,
            correlated_logs=correlated
        )

    def _find_correlated_events(self, alert: SecurityAlert) -> List[Dict[str, Any]]:
        events = []
        target_ip = alert.source_ip

        shadowpot_log = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
            "shadowpot", "logs", "shadowpot.json"
        )
        if target_ip and os.path.exists(shadowpot_log):
            try:
                with open(shadowpot_log, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line and target_ip in line:
                            data = json.loads(line)
                            events.append({
                                "source": "shadowpot",
                                "timestamp": data.get("timestamp"),
                                "event_type": data.get("event_type"),
                                "details": data.get("command") or data.get("username")
                            })
                            if len(events) >= 5:
                                break
            except Exception:
                pass

        return events
