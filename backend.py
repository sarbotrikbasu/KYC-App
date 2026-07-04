import os
import httpx
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv

load_dotenv()

app = FastAPI(title="KYC Verification API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

SANDBOX_BASE_URL = "https://api.sandbox.co.in"
API_KEY = os.getenv("SANDBOX_API_KEY", "")
API_SECRET = os.getenv("SANDBOX_API_SECRET", "")

# In-memory token store (MVP only)
token_store: dict = {"access_token": None}


class ConsentRequest(BaseModel):
    name: str
    consent: bool


class GenerateOTPRequest(BaseModel):
    aadhaar_number: str
    reason: str = "For KYC onboarding"


class VerifyOTPRequest(BaseModel):
    reference_id: str
    otp: str


class VerifyPANRequest(BaseModel):
    pan: str
    name_as_per_pan: str
    date_of_birth: str  # DD/MM/YYYY


@app.post("/api/authenticate")
async def authenticate():
    """Get access token from Sandbox using API key + secret."""
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{SANDBOX_BASE_URL}/authenticate",
            headers={
                "x-api-key": API_KEY,
                "x-api-secret": API_SECRET,
                "x-api-version": "1.0",
            },
        )
    data = resp.json()
    if data.get("code") != 200 or "data" not in data:
        sandbox_msg = data.get("message") or data.get("error") or str(data)
        raise HTTPException(
            status_code=401,
            detail=f"Sandbox authentication failed (HTTP {resp.status_code}): {sandbox_msg}"
        )
    token_store["access_token"] = data["data"]["access_token"]
    return {"success": True, "message": "Authenticated successfully"}


@app.post("/api/generate-otp")
async def generate_otp(req: GenerateOTPRequest):
    """Trigger OTP to the Aadhaar-linked mobile number."""
    token = token_store.get("access_token")
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated. Call /api/authenticate first.")

    if len(req.aadhaar_number) != 12 or not req.aadhaar_number.isdigit():
        raise HTTPException(status_code=422, detail="Aadhaar number must be exactly 12 digits.")

    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{SANDBOX_BASE_URL}/kyc/aadhaar/okyc/otp",
            headers={
                "Authorization": token,
                "x-api-key": API_KEY,
                "x-api-version": "2.0",
                "Content-Type": "application/json",
            },
            json={
                "@entity": "in.co.sandbox.kyc.aadhaar.okyc.otp.request",
                "aadhaar_number": req.aadhaar_number,
                "consent": "y",
                "reason": req.reason,
            },
        )

    data = resp.json()
    http_code = resp.status_code

    if http_code == 503:
        raise HTTPException(status_code=503, detail="UIDAI service unavailable. Please try again later.")
    if http_code == 422:
        raise HTTPException(status_code=422, detail=data.get("message", "Validation error"))
    if http_code == 401:
        raise HTTPException(status_code=401, detail="Token expired. Please re-authenticate.")

    otp_data = data.get("data", {})
    message = otp_data.get("message", "")

    if message == "Invalid Aadhaar Card":
        raise HTTPException(status_code=400, detail="Invalid Aadhaar number — not found in UIDAI records.")

    return {
        "success": True,
        "reference_id": str(otp_data.get("reference_id")),
        "message": message,
    }


@app.post("/api/verify-otp")
async def verify_otp(req: VerifyOTPRequest):
    """Verify the OTP and return Aadhaar demographic details."""
    token = token_store.get("access_token")
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated.")

    if len(req.otp) != 6 or not req.otp.isdigit():
        raise HTTPException(status_code=422, detail="OTP must be exactly 6 digits.")

    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{SANDBOX_BASE_URL}/kyc/aadhaar/okyc/otp/verify",
            headers={
                "Authorization": token,
                "x-api-key": API_KEY,
                "x-api-version": "2.0",
                "Content-Type": "application/json",
            },
            json={
                "@entity": "in.co.sandbox.kyc.aadhaar.okyc.request",
                "reference_id": req.reference_id,
                "otp": req.otp,
            },
        )

    data = resp.json()
    http_code = resp.status_code

    if http_code == 503:
        raise HTTPException(status_code=503, detail="UIDAI service unavailable.")
    if http_code == 422:
        raise HTTPException(status_code=422, detail=data.get("message", "Validation error"))

    otp_data = data.get("data", {})
    message = otp_data.get("message", "")
    status = otp_data.get("status", "")

    if message == "Invalid OTP":
        raise HTTPException(status_code=400, detail="Invalid OTP entered. Please try again.")
    if message == "OTP Expired":
        raise HTTPException(status_code=400, detail="OTP has expired (10 min limit). Please generate a new OTP.")
    if "under process" in message.lower():
        raise HTTPException(status_code=400, detail="Request under process. Please retry after 30 seconds.")

    if status != "VALID":
        raise HTTPException(status_code=400, detail=message or "Verification failed.")

    return {
        "success": True,
        "status": status,
        "name": otp_data.get("name"),
        "care_of": otp_data.get("care_of"),
        "gender": otp_data.get("gender"),
        "date_of_birth": otp_data.get("date_of_birth"),
        "year_of_birth": otp_data.get("year_of_birth"),
        "full_address": otp_data.get("full_address"),
        "email_hash": otp_data.get("email_hash"),
        "mobile_hash": otp_data.get("mobile_hash"),
        "share_code": otp_data.get("share_code"),
    }


@app.post("/api/verify-pan")
async def verify_pan(req: VerifyPANRequest):
    """Verify PAN and return name + status from ITD via Sandbox."""
    token = token_store.get("access_token")
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated.")

    pan = req.pan.strip().upper()
    import re
    if not re.fullmatch(r"[A-Z]{5}[0-9]{4}[A-Z]", pan):
        raise HTTPException(status_code=422, detail="Invalid PAN format. Expected format: ABCDE1234F")
    if not re.fullmatch(r"\d{2}/\d{2}/\d{4}", req.date_of_birth.strip()):
        raise HTTPException(status_code=422, detail="Date of birth must be in DD/MM/YYYY format.")
    if not req.name_as_per_pan.strip():
        raise HTTPException(status_code=422, detail="Name as per PAN is required.")

    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{SANDBOX_BASE_URL}/kyc/pan/verify",
            headers={
                "Authorization": token,
                "x-api-key": API_KEY,
                "x-api-version": "1.0",
                "Content-Type": "application/json",
            },
            json={
                "@entity": "in.co.sandbox.kyc.pan_verification.request",
                "pan": pan,
                "name_as_per_pan": req.name_as_per_pan.strip(),
                "date_of_birth": req.date_of_birth.strip(),
                "consent": "Y",
                "reason": "KYC verification for account onboarding",
            },
        )

    # Surface the real Sandbox response even when it is not valid JSON
    try:
        data = resp.json()
    except ValueError:
        raise HTTPException(
            status_code=502,
            detail=f"Sandbox returned non-JSON (HTTP {resp.status_code}): {resp.text[:300]}",
        )

    http_code = resp.status_code

    if http_code == 503:
        raise HTTPException(status_code=503, detail="Service unavailable. Please try again later.")
    if http_code in (401, 403):
        raise HTTPException(status_code=http_code, detail=data.get("message", "Authorization error. Check PAN subscription / wallet / token."))
    if http_code == 422:
        raise HTTPException(status_code=422, detail=data.get("message", "Validation error"))
    if http_code != 200:
        raise HTTPException(status_code=http_code, detail=data.get("message", str(data)))

    pan_data = data.get("data", {}) or {}
    status = str(pan_data.get("status", ""))

    if not pan_data or status.upper() != "VALID":
        raise HTTPException(
            status_code=400,
            detail=pan_data.get("remarks") or data.get("message") or f"PAN verification failed (status: {status or 'unknown'}).",
        )

    return {
        "success": True,
        "pan": pan_data.get("pan", pan),
        "status": status,
        "category": pan_data.get("category"),
        "name_as_per_pan_match": pan_data.get("name_as_per_pan_match"),
        "date_of_birth_match": pan_data.get("date_of_birth_match"),
        "aadhaar_seeding_status": pan_data.get("aadhaar_seeding_status"),
        "remarks": pan_data.get("remarks"),
    }
