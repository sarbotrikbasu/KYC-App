import streamlit as st
import requests

BACKEND_URL = "http://localhost:8000"

st.set_page_config(page_title="KYC Verification Portal", page_icon="🪪", layout="centered")

st.title("🪪 KYC Verification Portal")
st.caption("Powered by Sandbox.co.in")

# ── Session state initialisation ──────────────────────────────────────────────
defaults = {
    "authenticated": False,
    "user_name": None,
    # Aadhaar flow
    "aadhaar_step": "enter",       # enter | otp | result
    "aadhaar_reference_id": None,
    "aadhaar_result": None,
    # PAN flow
    "pan_result": None,
}
for key, val in defaults.items():
    if key not in st.session_state:
        st.session_state[key] = val


def call_backend(method: str, path: str, **kwargs):
    try:
        fn = getattr(requests, method)
        resp = fn(f"{BACKEND_URL}{path}", timeout=30, **kwargs)
        try:
            return resp.json(), resp.status_code
        except ValueError:
            # Non-JSON body (e.g. unhandled 500 returning plain text)
            return {"detail": f"Backend error (HTTP {resp.status_code}): {resp.text[:500]}"}, resp.status_code
    except requests.exceptions.ConnectionError:
        return {"detail": "Cannot connect to backend. Ensure FastAPI is running on port 8000."}, 503


# ══════════════════════════════════════════════════════════════════════════════
# PAGE 1 — Consent & Authentication (shown until authenticated)
# ══════════════════════════════════════════════════════════════════════════════
if not st.session_state.authenticated:
    st.subheader("Step 1 — Identity & Consent")

    with st.form("consent_form"):
        name = st.text_input("Full Name", placeholder="Enter your full name")
        st.markdown("---")
        st.markdown(
            "**Consent Statement**\n\n"
            "I hereby provide my explicit and informed consent to verify my identity "
            "through government-approved KYC mechanisms (Aadhaar OKYC / PAN ITD). I understand that:\n"
            "- For Aadhaar: a One-Time Password will be sent to my Aadhaar-registered mobile number.\n"
            "- For PAN: my PAN details will be fetched from the Income Tax Department.\n"
            "- My raw Aadhaar number will never be stored or exposed.\n"
            "- Data retrieved will be used solely for KYC verification purposes."
        )
        consent = st.checkbox("I agree to the above and provide my consent")
        submitted = st.form_submit_button("Proceed to KYC", type="primary")

    if submitted:
        if not name.strip():
            st.error("Please enter your full name.")
        elif not consent:
            st.error("You must provide consent to proceed.")
        else:
            with st.spinner("Authenticating with Sandbox..."):
                data, status = call_backend("post", "/api/authenticate")
            if status == 200:
                st.session_state.authenticated = True
                st.session_state.user_name = name.strip()
                st.rerun()
            else:
                st.error(f"Authentication failed: {data.get('detail', 'Unknown error')}")

    st.stop()


# ══════════════════════════════════════════════════════════════════════════════
# PAGE 2 — Tabbed KYC (shown after authentication)
# ══════════════════════════════════════════════════════════════════════════════
st.success(f"Authenticated · Welcome, **{st.session_state.user_name}**")

tab_aadhaar, tab_pan = st.tabs(["🔐 Aadhaar KYC", "📄 PAN KYC"])


# ─────────────────────────────────────────────────────────────────────────────
# TAB 1 — Aadhaar KYC
# ─────────────────────────────────────────────────────────────────────────────
with tab_aadhaar:

    # ── Sub-step: Enter Aadhaar ───────────────────────────────────────────────
    if st.session_state.aadhaar_step == "enter":
        st.subheader("Enter Aadhaar Number")
        st.info("Enter your 12-digit Aadhaar number to receive an OTP on your registered mobile.")

        with st.form("aadhaar_form"):
            aadhaar = st.text_input("Aadhaar Number", placeholder="123456789012", max_chars=12)
            submitted = st.form_submit_button("Send OTP", type="primary")

        if submitted:
            if len(aadhaar) != 12 or not aadhaar.isdigit():
                st.error("Please enter a valid 12-digit Aadhaar number.")
            else:
                with st.spinner("Sending OTP to your registered mobile..."):
                    data, status = call_backend(
                        "post", "/api/generate-otp",
                        json={"aadhaar_number": aadhaar, "reason": "For KYC onboarding"}
                    )
                if status == 200:
                    st.session_state.aadhaar_reference_id = data["reference_id"]
                    st.session_state.aadhaar_step = "otp"
                    st.rerun()
                else:
                    st.error(data.get("detail", "Failed to send OTP."))

    # ── Sub-step: Enter OTP ───────────────────────────────────────────────────
    elif st.session_state.aadhaar_step == "otp":
        st.subheader("Enter OTP")
        st.info("Enter the 6-digit OTP sent to your Aadhaar-registered mobile. Valid for **10 minutes**.")

        with st.form("otp_form"):
            otp = st.text_input("OTP", placeholder="Enter 6-digit OTP", max_chars=6)
            col_verify, col_resend = st.columns([2, 1])
            with col_verify:
                submitted = st.form_submit_button("Verify OTP", type="primary")
            with col_resend:
                resend = st.form_submit_button("Resend OTP")

        if resend:
            st.session_state.aadhaar_step = "enter"
            st.rerun()

        if submitted:
            if len(otp) != 6 or not otp.isdigit():
                st.error("Please enter a valid 6-digit OTP.")
            else:
                with st.spinner("Verifying OTP with UIDAI..."):
                    data, status = call_backend(
                        "post", "/api/verify-otp",
                        json={"reference_id": st.session_state.aadhaar_reference_id, "otp": otp}
                    )
                if status == 200:
                    st.session_state.aadhaar_result = data
                    st.session_state.aadhaar_step = "result"
                    st.rerun()
                else:
                    err = data.get("detail", "OTP verification failed.")
                    st.error(err)
                    if "expired" in err.lower():
                        if st.button("Generate New OTP"):
                            st.session_state.aadhaar_step = "enter"
                            st.rerun()

    # ── Sub-step: Result ──────────────────────────────────────────────────────
    elif st.session_state.aadhaar_step == "result":
        r = st.session_state.aadhaar_result or {}
        st.success("✅ Aadhaar KYC Verified Successfully")

        gender_map = {"M": "Male", "F": "Female", "T": "Transgender"}

        col1, col2 = st.columns(2)
        with col1:
            st.markdown(f"**Name:** {r.get('name', '—')}")
            st.markdown(f"**Date of Birth:** {r.get('date_of_birth') or r.get('year_of_birth', '—')}")
            st.markdown(f"**Gender:** {gender_map.get(r.get('gender', ''), r.get('gender', '—'))}")
        with col2:
            st.markdown(f"**Care of:** {r.get('care_of', '—')}")
            st.markdown(f"**Share Code:** {r.get('share_code', '—')}")

        st.markdown("---")
        st.markdown("**Address**")
        st.write(r.get("full_address") or "—")

        st.markdown("---")
        with st.expander("Hashed Contact Details"):
            st.markdown(f"**Email Hash (SHA-256):** `{r.get('email_hash', '—')}`")
            st.markdown(f"**Mobile Hash (SHA-256):** `{r.get('mobile_hash', '—')}`")

        st.markdown("---")
        if st.button("Verify Another Aadhaar", type="primary"):
            st.session_state.aadhaar_step = "enter"
            st.session_state.aadhaar_reference_id = None
            st.session_state.aadhaar_result = None
            st.rerun()


# ─────────────────────────────────────────────────────────────────────────────
# TAB 2 — PAN KYC
# ─────────────────────────────────────────────────────────────────────────────
with tab_pan:

    if st.session_state.pan_result is None:
        st.subheader("Enter PAN Details")
        st.info("PAN verification checks the PAN against Income Tax records and confirms whether the name and date of birth match. All three fields are required by the API.")

        with st.form("pan_form"):
            pan = st.text_input("PAN Number", placeholder="ABCDE1234F", max_chars=10)
            name_as_per_pan = st.text_input(
                "Name (exactly as printed on PAN card)",
                value=st.session_state.user_name or "",
            )
            dob = st.text_input("Date of Birth (DD/MM/YYYY)", placeholder="15/08/1990", max_chars=10)
            submitted = st.form_submit_button("Verify PAN", type="primary")

        if submitted:
            import re
            pan_clean = pan.strip().upper()
            if not re.fullmatch(r"[A-Z]{5}[0-9]{4}[A-Z]", pan_clean):
                st.error("Invalid PAN format. Expected: 5 letters + 4 digits + 1 letter (e.g., ABCDE1234F)")
            elif not name_as_per_pan.strip():
                st.error("Please enter the name exactly as printed on the PAN card.")
            elif not re.fullmatch(r"\d{2}/\d{2}/\d{4}", dob.strip()):
                st.error("Date of Birth must be in DD/MM/YYYY format (e.g., 15/08/1990).")
            else:
                with st.spinner("Verifying PAN with Income Tax Department..."):
                    data, status = call_backend(
                        "post", "/api/verify-pan",
                        json={
                            "pan": pan_clean,
                            "name_as_per_pan": name_as_per_pan.strip(),
                            "date_of_birth": dob.strip(),
                        },
                    )
                if status == 200:
                    st.session_state.pan_result = data
                    st.rerun()
                else:
                    st.error(data.get("detail", "PAN verification failed."))

    else:
        r = st.session_state.pan_result or {}
        st.success("✅ PAN Verified Successfully")

        seeding_map = {"y": "Linked", "n": "Not Linked", "na": "Not Applicable"}

        col1, col2 = st.columns(2)
        with col1:
            st.markdown(f"**PAN:** {r.get('pan', '—')}")
            st.markdown(f"**Status:** {r.get('status', '—')}")
            st.markdown(f"**Category:** {r.get('category', '—')}")
        with col2:
            seeding = str(r.get("aadhaar_seeding_status", "")).lower()
            st.markdown(f"**Aadhaar Seeding:** {seeding_map.get(seeding, r.get('aadhaar_seeding_status', '—'))}")
            if r.get("remarks"):
                st.markdown(f"**Remarks:** {r.get('remarks')}")

        st.markdown("---")
        st.markdown("**Identity Match Results**")
        c1, c2 = st.columns(2)
        with c1:
            name_match = r.get("name_as_per_pan_match")
            st.markdown(f"**Name Match:** {'✅ Match' if name_match else '❌ No Match'}")
        with c2:
            dob_match = r.get("date_of_birth_match")
            st.markdown(f"**DOB Match:** {'✅ Match' if dob_match else '❌ No Match'}")

        st.markdown("---")
        if st.button("Verify Another PAN", type="primary"):
            st.session_state.pan_result = None
            st.rerun()
