# TrustGuard 2030

Megatrends: AI + Demographics + Trust

Target group: Seniors (and caregivers) in 2030.

Problem: AI‑powered scams and deepfakes make it hard to know what to trust. Seniors face higher risk of digital fraud and consent confusion.

Solution: A simple assistant to check messages for risk using OpenAI, manage trusted contacts with shared safe words, and generate clear consent/report templates.

## Quickstart (Windows PowerShell)
```powershell
cd trustguard-2030
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt

# Run the app (OpenAI only for message checks)
streamlit run app.py
```
### Enable AI (required for message checks)
- Set your API key without committing it:
```powershell
$env:OPENAI_API_KEY = "sk-..."
```
- Or create a `.env` file (copy `.env.example`) and set `OPENAI_API_KEY`.
- In the app, use "Analyze with OpenAI".

Open the URL printed by Streamlit (usually http://localhost:8501).

## Features
- Message Risk Check: paste text; get a risk score and flagged issues.
- Trusted Contacts: store contacts + a hashed safe word; verify calls.
- Templates: generate a consent letter or scam report; download as text.
- Learn: fast checklist to avoid the most common 2030 scams.

## Data and Privacy
Data stays on your machine. Trusted contacts are saved to `data/trusted_contacts.json` locally. No network calls or external APIs.

## Notes
Prototype for the Megatrends Challenge. Expand with phone spam detection, voice passphrases, and verified sender registries.
