import os
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
packages_dir = BASE_DIR / "packages"
if packages_dir.exists() and str(packages_dir) not in sys.path:
    sys.path.insert(0, str(packages_dir))

try:
    from dotenv import load_dotenv
    load_dotenv(BASE_DIR / ".env", override=True)
except ImportError:
    env_path = BASE_DIR / ".env"
    if env_path.exists():
        with open(env_path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    os.environ[k.strip()] = v.strip()

class Settings:
    APP_NAME: str = os.getenv("APP_NAME", "MailGuardian AI")
    APP_ENV: str = os.getenv("APP_ENV", "development")
    DEBUG: bool = os.getenv("DEBUG", "True").lower() in ("true", "1", "yes")
    HOST: str = os.getenv("HOST", "0.0.0.0")
    PORT: int = int(os.getenv("PORT", "8000"))
    
    # API Keys
    ABUSEIPDB_API_KEY: str = os.getenv("ABUSEIPDB_API_KEY", "").strip()
    ALIENVAULT_OTX_API_KEY: str = os.getenv("ALIENVAULT_OTX_API_KEY", "").strip()
    IPINFO_TOKEN: str = os.getenv("IPINFO_TOKEN", "").strip()

    @property
    def VIRUSTOTAL_API_KEYS(self) -> list[str]:
        raw = os.getenv("VIRUSTOTAL_API_KEYS", "").strip()
        single = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
        keys = []
        if raw:
            keys = [k.strip() for k in raw.split(",") if k.strip()]
        if single and single not in keys:
            keys.append(single)
        return keys

    @property
    def VIRUSTOTAL_API_KEY(self) -> str:
        keys = self.VIRUSTOTAL_API_KEYS
        return keys[0] if keys else ""

    # OpenRouter & Gemini AI Intelligence
    OPENROUTER_API_KEY: str = os.getenv("OPENROUTER_API_KEY", "").strip()
    OPENROUTER_MODEL: str = os.getenv("OPENROUTER_MODEL", "qwen/qwen-2.5-72b-instruct").strip()

    @property
    def GEMINI_API_KEYS(self) -> list[str]:
        keys = []
        for env_k in ["GEMINI_API_KEY_1", "GEMINI_API_KEY_2", "GEMINI_API_KEY_3"]:
            val = os.getenv(env_k, "").strip()
            if val and val not in keys:
                keys.append(val)
        return keys

    GEMINI_PRIMARY_MODEL: str = os.getenv("GEMINI_PRIMARY_MODEL", "gemini-2.5-flash").strip()
    GEMINI_DOWNGRADE_MODEL: str = os.getenv("GEMINI_DOWNGRADE_MODEL", "gemini-2.5-flash").strip()


    # Cache and storage
    DATA_DIR: Path = BASE_DIR / "data"
    DB_PATH: Path = BASE_DIR / "data" / "securex.db"
    MODEL_DIR: Path = BASE_DIR / "ml"
    MODEL_PATH: Path = BASE_DIR / "ml" / "model.pkl"
    REPORTS_DIR: Path = BASE_DIR / "reports"

    # Cache TTLs (7 days: 7 * 86400 = 604800s)
    CACHE_TTL_DAYS: int = int(os.getenv("CACHE_TTL_DAYS", "7"))
    THREAT_CACHE_TTL: int = int(os.getenv("CACHE_TTL_SECONDS", "604800"))
    WHOIS_CACHE_TTL: int = int(os.getenv("WHOIS_CACHE_TTL", "604800"))
    GEO_CACHE_TTL: int = int(os.getenv("GEO_CACHE_TTL", "604800"))

    # Risk thresholds & scoring version
    SCORING_VERSION: str = "2026.1"
    LOCAL_LOW_THRESHOLD: float = 50.0
    LOCAL_HIGH_THRESHOLD: float = 70.0
    CLEAN_THRESHOLD: float = 30.0
    SUSPICIOUS_THRESHOLD: float = 60.0

    # Trust Model Configuration
    # Only Authentication-Results headers whose authserv-id matches these will be trusted
    @property
    def TRUSTED_AUTHSERV_IDS(self) -> list[str]:
        raw = os.getenv("TRUSTED_AUTHSERV_IDS", "mailguardian.internal,mx.corporate.in,protection.outlook.com,google.com").strip()
        return [item.strip().lower() for item in raw.split(",") if item.strip()]

    # Configured organizational relays and boundary MTAs (CIDR or IPs)
    @property
    def TRUSTED_RELAYS(self) -> list[str]:
        raw = os.getenv("TRUSTED_RELAYS", "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8").strip()
        return [item.strip() for item in raw.split(",") if item.strip()]

    # Known trustworthy major mail infrastructure domains for relay metadata evaluation
    TRUSTED_PROVIDER_DOMAINS: list[str] = [
        "google.com", "outlook.com", "microsoft.com", "amazonses.com", "sendgrid.net", "mailgun.org"
    ]

    # Threat Intel timeouts and privacy settings
    THREAT_INTEL_TIMEOUT_SECONDS: float = float(os.getenv("THREAT_INTEL_TIMEOUT_SECONDS", "4.0"))

    # Secure Processing & TEE Enclave Configuration
    # Modes: "standard" (in-process) | "enclave" (AWS Nitro Enclave TEE interface)
    SECURE_MODE: str = os.getenv("SECURE_MODE", "standard").strip().lower()

settings = Settings()
settings.DATA_DIR.mkdir(parents=True, exist_ok=True)
settings.REPORTS_DIR.mkdir(parents=True, exist_ok=True)
settings.MODEL_DIR.mkdir(parents=True, exist_ok=True)
