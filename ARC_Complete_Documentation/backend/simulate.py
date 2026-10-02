import requests
import json
import time
from datetime import datetime
import uuid

API_URL = "http://localhost:8000/api/v1/events"
HEADERS = {
    "Content-Type": "application/json",
    "X-ARC-API-KEY": "dev-test-key"
}

def send_event(event_type: str, action: str, src_ip: str, user: str, status: str = "failure"):
    payload = {
        "source": "windows",
        "payload": {
            "event_id": str(uuid.uuid4()),
            "timestamp": datetime.utcnow().isoformat(),
            "host": "LAB-WIN01",
            "username": user,
            "src_ip": src_ip,
            "event_type": event_type,
            "action": action,
            "status": status
        }
    }
    
    try:
        response = requests.post(API_URL, headers=HEADERS, data=json.dumps(payload))
        print(f"Sent {event_type} - {action} for user {user} from {src_ip}. Status: {response.status_code}")
    except requests.exceptions.ConnectionError:
        print(f"Connection failed. Ensure the API is running at {API_URL}")

def simulate_brute_force():
    print("--- Simulating Repeated Auth Failure (Brute Force) ---")
    for _ in range(5):
        send_event(event_type="auth_failed", action="login", src_ip="192.168.1.105", user="admin")
        time.sleep(0.5)

def simulate_password_spray():
    print("--- Simulating Password Spray ---")
    users = ["admin", "root", "test", "user1", "user2"]
    for user in users:
        send_event(event_type="auth_failed", action="login", src_ip="10.10.10.55", user=user)
        time.sleep(0.5)

def simulate_suspicious_process():
    print("--- Simulating Suspicious Process Creation (PowerShell) ---")
    # In a real system, the detection rule would look for powershell.exe with encoded commands
    payload = {
        "source": "windows",
        "payload": {
            "event_id": str(uuid.uuid4()),
            "timestamp": datetime.utcnow().isoformat(),
            "host": "LAB-WIN02",
            "username": "jdoe",
            "event_type": "process_creation",
            "process_name": "powershell.exe",
            "parent_process": "cmd.exe",
            "command_line": "powershell.exe -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtACgAWwBDAG8AbgB2AGUAcgB0AF0AOgA6AEYAcgBvAG0AQgBhAHMAZQA2ADQAUwB0AHIAaQBuAGcAKAAiAEgA..."
        }
    }
    try:
        response = requests.post(API_URL, headers=HEADERS, data=json.dumps(payload))
        print(f"Sent Suspicious Process Creation. Status: {response.status_code}")
    except requests.exceptions.ConnectionError:
        print(f"Connection failed. Ensure the API is running at {API_URL}")

if __name__ == "__main__":
    print("Starting ARC Attack Simulations (Synthetic Telemetry)")
    simulate_brute_force()
    time.sleep(2)
    simulate_password_spray()
    time.sleep(2)
    simulate_suspicious_process()
    print("Simulations complete.")
