import logging
import os
import requests
from arc.correlation.store import get_context, store_context

logger = logging.getLogger(__name__)

VT_API_KEY = os.getenv("VT_API_KEY", "")

def check_ip_reputation(ip_address: str) -> dict:
    """Check IP against VirusTotal with Redis caching."""
    cache_key = f"intel:vt:ip:{ip_address}"
    cached = get_context(cache_key)
    if cached:
        return cached

    if not VT_API_KEY:
        return {"error": "VT_API_KEY not configured", "malicious": False}

    headers = {"x-apikey": VT_API_KEY}
    try:
        response = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}", headers=headers)
        if response.status_code == 200:
            data = response.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            result = {
                "malicious": stats.get("malicious", 0) > 0,
                "stats": stats
            }
            store_context(cache_key, result, 86400) # Cache for 24 hours
            return result
    except Exception as e:
        logger.error(f"Failed to query VT: {e}")
    
    return {"malicious": False}
