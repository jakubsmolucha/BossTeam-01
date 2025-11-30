import io
import streamlit as st

from trustguard.llm import llm_assess_message
import os
from trustguard.storage import load_contacts, save_contacts, hash_safe_word, verify_safe_word
from trustguard.templates import generate_report

st.set_page_config(page_title="TrustGuard 2030", page_icon="🛡️", layout="centered")

st.title("🛡️ TrustGuard 2030")

st.markdown(
    """
TrustGuard helps you:
- Check if a message looks risky
- Keep a small list of trusted contacts with a shared safe word
- Generate clear consent and report templates you can download

All data stays on your device. No cloud or external APIs.
"""
)

# Show OpenAI key status banner
api_present = bool(os.getenv("OPENAI_API_KEY"))

# Tabs
check_tab, contacts_tab, report_tab, learn_tab = st.tabs([
    "Check a Message", "Trusted Contacts", "Report", "Learn"
])

with check_tab:
    st.subheader("Check a Message")
    sample = """URGENT: Your account will be suspended in 24 hours! Click https://rnicrosoft.com-login.example.zip to verify your password and 2FA code now!"""
    msg = st.text_area("Paste the message or email text:", height=180, value=sample)
    sender = st.text_input("Sender (email/domain or name)", placeholder="e.g., no-reply@google.com or google.com")
    allow = st.text_input("Allowlist brands/domains (comma-separated)", placeholder="e.g., google.com, microsoft.com")
    st.caption("Uses OpenAI only. Set OPENAI_API_KEY before analyzing.")
    if st.button("Analyze with OpenAI"):
        try:
            allowlist = [a.strip() for a in (allow or "").split(",") if a.strip()]
            ai = llm_assess_message(msg, sender=sender, allowlist=allowlist)
            st.markdown(f"### Risk (OpenAI): {ai['verdict']} ({ai['score']}/100)")
            st.progress(ai['score'] / 100)
            st.caption(f"Confidence: {ai.get('confidence', 0.6):.2f}")
            if ai.get("reasons"):
                st.markdown("**Reasons**")
                for r in ai["reasons"]:
                    st.write(f"- {r}")
            if ai.get("advice"):
                st.markdown("**Advice**")
                for a in ai["advice"]:
                    st.write(f"- {a}")
        except Exception as e:
            st.error(f"AI check failed: {e}")
            st.caption("Set OPENAI_API_KEY and try again.")
        st.markdown("**Next steps**")
        st.write("- Do not share codes or passwords.")
        st.write("- Call the organization using a number from their official website.")
        st.write("- If a trusted contact is relevant, verify with your shared safe word.")

with contacts_tab:
    st.subheader("Trusted Contacts")
    st.caption("People you can safely speak to about accounts, appointments, and emergencies.")

    contacts = load_contacts()

    with st.expander("Add or Update Contact"):
        name = st.text_input("Name")
        channel = st.text_input("Phone or Email")
        safe_word = st.text_input("Shared Safe Word (you both know)", type="password")
        if st.button("Save Contact"):
            if not name or not channel or not safe_word:
                st.error("Please fill in all fields.")
            else:
                hashed = hash_safe_word(safe_word)
                # Replace if exists
                remaining = [c for c in contacts if c.get("name") != name]
                remaining.append({"name": name, "channel": channel, "safe_hash": hashed})
                save_contacts(remaining)
                st.success(f"Saved contact: {name}")
                contacts = remaining

    if contacts:
        st.markdown("**Your Contacts**")
        for c in contacts:
            st.write(f"- {c['name']} · {c['channel']}")
    else:
        st.info("No contacts yet. Add one above.")

    st.divider()
    st.markdown("**Verify a Safe Word**")
    if contacts:
        pick = st.selectbox("Choose contact", [c["name"] for c in contacts])
        attempt = st.text_input("What is our safe word?", type="password")
        if st.button("Verify"):
            contact = next((c for c in contacts if c["name"] == pick), None)
            if contact and verify_safe_word(contact["safe_hash"], attempt):
                st.success("Match. You can trust this conversation starter.")
            else:
                st.error("No match. Hang up and call back via your own contact list.")
    else:
        st.caption("Add a contact to enable verification.")

with report_tab:
    st.subheader("Scam Report")
    r_name = st.text_input("Your Name", key="report_name")
    r_contact = st.text_input("Your Phone or Email", key="report_contact")
    r_summary = st.text_area("What happened?", key="report_summary")
    if st.button("Generate Report"):
        if not r_name or not r_contact or not r_summary:
            st.error("Please fill in all fields.")
        else:
            rep = generate_report(r_name, r_contact, r_summary)
            st.text_area("Preview", rep, height=160)
            st.download_button("Download as .txt", data=rep.encode("utf-8"), file_name="scam_report.txt")

with learn_tab:
    st.subheader("Learn: 10 Quick Safeguards")
    tips = [
        "Use a shared safe word with a trusted contact.",
        "Never share 2FA codes, OTPs, or passwords.",
        "Pause: urgent threats push quick decisions.",
        "Check the sender's address; beware lookalike domains.",
        "Type official websites yourself; avoid clicking links.",
        "If unsure, call back using a number you already trust.",
        "Ignore payment via gift cards, crypto, or wire transfers.",
        "Be wary of mixed scripts or odd characters in links.",
        "Keep devices up to date; enable multifactor auth.",
        "Talk to family/caregivers before large decisions."
    ]
    for t in tips:
        st.write(f"- {t}")

# Hide deploy button
hide_streamlit_style = """
    <style>
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    [data-testid="stToolbar"] {visibility: hidden !important;}
    </style>
"""
st.markdown(hide_streamlit_style, unsafe_allow_html=True)