import os
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel
from supabase import Client, create_client
from dotenv import load_dotenv

load_dotenv()

app = FastAPI()

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
EXPECTED_EXE_HASH = os.getenv("EXPECTED_EXE_HASH", "")

try:
    supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
except Exception:
    supabase = None

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

class LoginRequest(BaseModel):
    username: str
    password: str  
    hwid: str
    exe_hash: str

class VerifySessionRequest(BaseModel):
    username: str
    hwid: str
    session_token: str

# --- 1. ระบบยืนยันตัวตนบน Server ---
@app.post("/api/login")
def login(req: LoginRequest):
    if not supabase:
        raise HTTPException(status_code=500, detail="Database connection error")

    # 1.1 เช็ค Hash โปรแกรมบน Server
    expected_hash = EXPECTED_EXE_HASH.strip().lower()
    client_hash = req.exe_hash.strip().lower()

    if expected_hash and client_hash != expected_hash and client_hash != "dev_mode_no_hash":
        raise HTTPException(status_code=403, detail="Unauthorized client version")

    # 1.2 เช็ค User / Password บน Server
    res = (
        supabase.table("users")
        .select("password_hash", "expire_date", "hwid")
        .eq("username", req.username)
        .execute()
    )
    if not res.data:
        return {"success": False, "message": "ไม่พบผู้ใช้งานในระบบ"}

    user = res.data[0]

    if user["password_hash"] != hash_password(req.password):
        return {"success": False, "message": "รหัสผ่านไม่ถูกต้อง"}

    # 1.3 เช็ค วันหมดอายุ บน Server
    expire_str = user.get("expire_date")
    if expire_str:
        try:
            expire_dt = datetime.fromisoformat(expire_str.replace("Z", "+00:00"))
            if datetime.now(timezone.utc) > expire_dt:
                return {"success": False, "message": "เวลาการใช้งานของคุณหมดอายุแล้ว"}
        except Exception:
            return {"success": False, "message": "รูปแบบวันที่ไม่ถูกต้อง"}

    # 1.4 เช็ค HWID ล็อคเครื่อง บน Server
    reg_hwid = user.get("hwid")
    if not reg_hwid or reg_hwid in ["EMPTY", "UNKNOWN_DEVICE"]:
        # ผูกเครื่องแรกเข้ากับบัญชี
        supabase.table("users").update({"hwid": req.hwid}).eq("username", req.username).execute()
    elif reg_hwid != req.hwid:
        return {"success": False, "message": "บัญชีนี้ผูกไว้กับเครื่องอื่นแล้ว"}

    # 1.5 สร้าง Session Token คืนให้ Client และอัปเดตลง Supabase
    session_token = secrets.token_hex(32)
    supabase.table("users").update({"session_token": session_token}).eq("username", req.username).execute()
    
    return {
        "success": True,
        "message": "เข้าสู่ระบบสำเร็จ",
        "session_token": session_token,
        "expire_date": user.get("expire_date")
    }

# --- 2. เช็คสถานะการทำงานสม่ำเสมอ (Heartbeat Check) ---
@app.post("/api/verify_session")
def verify_session(req: VerifySessionRequest):
    if not supabase:
        return {"active": False}

    res = supabase.table("users").select("expire_date", "hwid", "session_token").eq("username", req.username).execute()
    if not res.data:
        return {"active": False}
    
    user = res.data[0]
    
    # เช็ค HWID และ Session Token ตรงกับที่บันทึกไว้ใน DB หรือไม่
    if user.get("hwid") != req.hwid or user.get("session_token") != req.session_token:
        return {"active": False}
        
    expire_str = user.get("expire_date")
    if expire_str:
        try:
            expire_dt = datetime.fromisoformat(expire_str.replace("Z", "+00:00"))
            if datetime.now(timezone.utc) > expire_dt:
                return {"active": False}
        except Exception:
            return {"active": False}

    return {"active": True}
