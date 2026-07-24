import os
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from fastapi import FastAPI, HTTPException
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

class RegisterRequest(BaseModel):
    username: str
    password: str

class RedeemRequest(BaseModel):
    username: str
    key_code: str

# --- 1. ระบบสมัครสมาชิก (Register) ---
@app.post("/api/register")
def register(req: RegisterRequest):
    if not supabase:
        raise HTTPException(status_code=500, detail="Database connection error")

    if not req.username or not req.password:
        return {"success": False, "message": "กรุณากรอก Username และ Password ให้ครบถ้วน"}

    res = supabase.table("users").select("username").eq("username", req.username).execute()
    if res.data:
        return {"success": False, "message": "Username นี้ถูกใช้งานไปแล้ว"}

    hashed_pwd = hash_password(req.password)

    try:
        data = {
            "username": req.username,
            "password_hash": hashed_pwd,
            "hwid": "EMPTY",
            "expire_date": None  # เริ่มต้นยังไม่มีวันใช้งาน ต้องเติม Key ก่อน
        }
        supabase.table("users").insert(data).execute()
        return {"success": True, "message": "สมัครสมาชิกสำเร็จ! กรุณาเติม Serial Key ก่อนเข้าใช้งาน"}
    except Exception as e:
        return {"success": False, "message": f"ไม่สามารถสร้างบัญชีได้: {str(e)}"}

# --- 2. ระบบเข้าสู่ระบบ (Login) --- [บล็อกคนไม่มี Key แล้ว!]
@app.post("/api/login")
def login(req: LoginRequest):
    if not supabase:
        raise HTTPException(status_code=500, detail="Database connection error")

    expected_hash = EXPECTED_EXE_HASH.strip().lower()
    client_hash = req.exe_hash.strip().lower()

    if expected_hash and client_hash != expected_hash and client_hash != "dev_mode_no_hash":
        return {"success": False, "message": "เวอร์ชันโปรแกรมไม่ถูกต้อง กรุณาอัปเดต"}

    res = (
        supabase.table("users")
        .select("password_hash", "expire_date", "hwid")
        .eq("username", req.username)
        .execute()
    )
    if not res.data:
        return {"success": False, "message": "ไม่พบผู้ใช้งานในระบบ"}

    user = res.data[0]

    # เช็ครหัสผ่าน
    if user["password_hash"] != hash_password(req.password):
        return {"success": False, "message": "รหัสผ่านไม่ถูกต้อง"}

    expire_str = user.get("expire_date")

    # 🔴 [ล็อกบ้าน] ถ้าไม่มีวันหมดอายุ (ยังไม่ได้เติม Key) ห้ามเข้าเด็ดขาด!
    if not expire_str:
        return {"success": False, "message": "บัญชีนี้ยังไม่ได้เติม Serial Key กรุณาไปที่แท็บ Redeem Key ก่อน"}

    # เช็คว่าวันใช้งานหมดอายุหรือยัง
    try:
        expire_dt = datetime.fromisoformat(expire_str.replace("Z", "+00:00"))
        if datetime.now(timezone.utc) > expire_dt:
            return {"success": False, "message": "เวลาการใช้งานของคุณหมดอายุแล้ว กรุณาเติม Key เพิ่ม"}
    except Exception:
        return {"success": False, "message": "รูปแบบวันที่ในระบบไม่ถูกต้อง"}

    # เช็ค HWID (ผูกเครื่อง)
    reg_hwid = user.get("hwid")
    if not reg_hwid or reg_hwid in ["EMPTY", "UNKNOWN_DEVICE"]:
        supabase.table("users").update({"hwid": req.hwid}).eq("username", req.username).execute()
    elif reg_hwid != req.hwid:
        return {"success": False, "message": "บัญชีนี้ผูกไว้กับเครื่องอื่นแล้ว"}

    session_token = secrets.token_hex(32)
    supabase.table("users").update({"session_token": session_token}).eq("username", req.username).execute()
    
    return {
        "success": True,
        "message": "เข้าสู่ระบบสำเร็จ",
        "session_token": session_token,
        "expire_date": user.get("expire_date")
    }

# --- 3. เช็คสถานะ Session (Heartbeat) ---
@app.post("/api/verify_session")
def verify_session(req: VerifySessionRequest):
    if not supabase:
        return {"active": False}

    res = supabase.table("users").select("expire_date", "hwid", "session_token").eq("username", req.username).execute()
    if not res.data:
        return {"active": False}
    
    user = res.data[0]
    
    if user.get("hwid") != req.hwid or user.get("session_token") != req.session_token:
        return {"active": False}
        
    expire_str = user.get("expire_date")
    if not expire_str:
        return {"active": False}

    try:
        expire_dt = datetime.fromisoformat(expire_str.replace("Z", "+00:00"))
        if datetime.now(timezone.utc) > expire_dt:
            return {"active": False}
    except Exception:
        return {"active": False}

    return {"active": True}

# --- 4. ระบบเติม Serial Key (Redeem) ---
@app.post("/api/redeem")
def redeem_key(req: RedeemRequest):
    if not supabase:
        raise HTTPException(status_code=500, detail="Database connection error")

    user_res = supabase.table("users").select("expire_date").eq("username", req.username).execute()
    if not user_res.data:
        return {"success": False, "message": "ไม่พบ Username นี้ในระบบ"}

    key_res = supabase.table("keys").select("*").eq("key_code", req.key_code).eq("is_used", False).execute()
    if not key_res.data:
        return {"success": False, "message": "Serial Key ไม่ถูกต้อง หรือถูกใช้งานไปแล้ว"}

    key_info = key_res.data[0]
    days_to_add = key_info.get("days", 30)

    current_expire = user_res.data[0].get("expire_date")
    now_utc = datetime.now(timezone.utc)
    
    if current_expire:
        try:
            exp_dt = datetime.fromisoformat(current_expire.replace("Z", "+00:00"))
            base_time = max(now_utc, exp_dt)
        except Exception:
            base_time = now_utc
    else:
        base_time = now_utc

    new_expire = base_time + timedelta(days=days_to_add)

    # อัปเดตวันหมดอายุ และตัดใช้งาน Key
    supabase.table("users").update({"expire_date": new_expire.isoformat()}).eq("username", req.username).execute()
    supabase.table("keys").update({"is_used": True, "used_by": req.username}).eq("key_code", req.key_code).execute()

    return {"success": True, "message": f"เติม Key สำเร็จ! เพิ่มวันใช้งาน {days_to_add} วัน"}
