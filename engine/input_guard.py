import re
import unicodedata
from typing import Tuple, Optional, Any

INJECTION_PATTERNS = [
    r"(?i)ignore\s+(all\s+)?(previous\s+|prior\s+|above\s+|preceding\s+)?(instructions|prompts|rules|commands)",
    r"(?i)system\s+override",
    r"(?i)disregard\s+(all\s+)?(the\s+)?(guardrails|guidelines|policies|constraints|instructions)",
    r"(?i)forget\s+(all\s+)?(previous|prior|above)\s+(instructions|rules)",
    r"(?i)you\s+are\s+now\s+(in\s+)?(developer\s+mode|unrestricted|dan)",
    r"(?i)bypass\s+all\s+(filters|safety|guardrails)",
    r"(?i)<\/?system>",
    r"(?i)<\/?instruction>",
    r"(?i)<\/?untrusted_alert_telemetry>",
    r"(?i)\[INST\]|\[\/INST\]"
]

COMPILED_PATTERNS = [re.compile(p) for p in INJECTION_PATTERNS]

HOMOGLYPH_MAP = str.maketrans(
    "аеорсхуіјѕАЕОРСХУІЈЅ",
    "aeopcxyijsAEOPCXYIJS"
)

class AlertSanitizer:
    @staticmethod
    def normalize_text(text: str) -> str:
        if not text:
            return ""
        cleaned = re.sub(r"[\u200B-\u200D\uFEFF\u00AD\u2060\u200E\u200F]", "", text)
        cleaned = unicodedata.normalize("NFKC", cleaned)
        cleaned = cleaned.translate(HOMOGLYPH_MAP)
        return cleaned

    @staticmethod
    def inspect(content: str) -> Tuple[bool, Optional[str]]:
        if not content or not str(content).strip():
            return True, None
        normalized = AlertSanitizer.normalize_text(str(content))
        for pattern in COMPILED_PATTERNS:
            match = pattern.search(normalized)
            if match:
                return False, f"Potential prompt injection detected: {match.group(0)}"
        return True, None

    @staticmethod
    def sanitize(text: Any) -> str:
        if text is None:
            return ""
        val = str(text)
        cleaned = AlertSanitizer.normalize_text(val)
        cleaned = cleaned.replace("<", "&lt;").replace(">", "&gt;")
        cleaned = cleaned.replace("[INST]", "").replace("[/INST]", "")
        return cleaned.strip()

    @staticmethod
    def wrap_untrusted(data: str) -> str:
        sanitized = AlertSanitizer.sanitize(data)
        return f"<untrusted_alert_telemetry>\n{sanitized}\n</untrusted_alert_telemetry>"
