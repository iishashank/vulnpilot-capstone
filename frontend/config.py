import os


API_BASE_URL = os.getenv("VULNPILOT_API_URL", "http://127.0.0.1:8000").rstrip("/")
_api_key = os.getenv("VULNPILOT_API_KEY", "").strip()
API_REQUEST_HEADERS = {"X-API-Key": _api_key} if _api_key else {}
