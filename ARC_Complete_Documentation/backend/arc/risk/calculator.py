def calculate_risk_score(event: dict, detection_severity: str, intel_context: dict) -> int:
    """
    Calculates a dynamic risk score (0-100) based on event context and intel.
    """
    base_score = {
        "Low": 20,
        "Medium": 50,
        "High": 80,
        "Critical": 95
    }.get(detection_severity, 10)
    
    # Increase risk if VT says malicious
    if intel_context and intel_context.get("malicious"):
        base_score = min(100, base_score + 25)
        
    return base_score
