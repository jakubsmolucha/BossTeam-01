from datetime import date


def generate_report(name: str, channel: str, summary: str):
    today = date.today().isoformat()
    return f"""
Suspected Scam Report
Date: {today}
Reporter: {name}
Contact: {channel}

Summary of Incident:
{summary}

Requested Action:
Please acknowledge receipt and advise on next steps. I consent to share this report with relevant authorities.
""".strip()
