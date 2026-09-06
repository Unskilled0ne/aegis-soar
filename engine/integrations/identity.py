import logging
from typing import Dict, Any

logger = logging.getLogger("soar.identity")

class IdentityService:
    def __init__(self, driver: str = "mock_okta"):
        self.driver = driver
        self.revoked_sessions = []
        self.disabled_accounts = []

    def revoke_user_sessions(self, user_identity: str) -> Dict[str, Any]:
        """
        Revokes active OAuth tokens, MFA sessions, and SSO tickets for user.
        """
        self.revoked_sessions.append(user_identity)
        logger.info(f"[Identity] Revoked all active SSO sessions for user: {user_identity}")
        return {
            "status": "success",
            "action": "SESSION_REVOCATION",
            "target_user": user_identity,
            "cleared_sessions": 3,
            "driver": self.driver
        }

    def disable_account(self, user_identity: str, reason: str) -> Dict[str, Any]:
        """
        Locks user account in Okta / Active Directory to prevent lateral movement.
        """
        self.disabled_accounts.append(user_identity)
        logger.info(f"[Identity] Account DISABLED for {user_identity}. Reason: {reason}")
        return {
            "status": "success",
            "action": "ACCOUNT_DISABLED",
            "target_user": user_identity,
            "reason": reason,
            "driver": self.driver
        }
