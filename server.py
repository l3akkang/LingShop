import os
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from fastapi import FastAPI, HTTPException, Header, Depends
from pydantic import BaseModel
from supabase import Client, create_client
from dotenv import load_dotenv

load_dotenv()

app = FastAPI()

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
EXPECTED_EXE_HASH = os.getenv("EXPECTED_EXE_HASH", "").strip().lower()

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

class HeartbeatRequest(BaseModel):
    username: str
    hwid: str

class RegisterRequest(BaseModel):
    username: str
    password: str

class RedeemRequest(BaseModel):
    username: str
    key_code: str

@app.post("/api/register")
def register(req: RegisterRequest):
    if not supabase:
        raise HTTPException(status_code=500, detail="Database connection error")
    if not req.username or not req.password:
        return {"success": False, "message": "กรุณากรอกข้อมูลให้ครบถ้วน"}

    res = supabase.table("users").select("username").eq("username", req.username).execute()
    if res.data:
        return {"success": False, "message": "Username ถูกใช้งานแล้ว"}

    try:
        data = {
            "username": req.username,
            "password_hash": hash_password(req.password),
            "hwid": "EMPTY",
            "expire_date": None
        }
        supabase.table("users").insert(data).execute()
        return {"success": True, "message": "สมัครสมาชิกสำเร็จ!"}
    except Exception as e:
        return {"success": False, "message": f"เกิดข้อผิดพลาด: {str(e)}"}

@app.post("/api/login")
def login(req: LoginRequest):
    if not supabase:
        raise HTTPException(status_code=500, detail="Database connection error")

    # Anti-Tamper Check Hash
    client_hash = req.exe_hash.strip().lower()
    if EXPECTED_EXE_HASH and client_hash != EXPECTED_EXE_HASH and client_hash != "dev_mode_no_hash":
        return {"success": False, "message": "เวอร์ชันโปรแกรมไม่ถูกต้อง"}

    res = supabase.table("users").select("password_hash", "expire_date", "hwid").eq("username", req.username).execute()
    if not res.data:
        return {"success": False, "message": "ไม่พบผู้ใช้งาน"}

    user = res.data[0]
    if user["password_hash"] != hash_password(req.password):
        return {"success": False, "message": "รหัสผ่านไม่ถูกต้อง"}

    expire_str = user.get("expire_date")
    if not expire_str:
        return {"success": False, "message": "บัญชีนี้ยังไม่ได้เติม Serial Key"}

    try:
        expire_dt = datetime.fromisoformat(expire_str.replace("Z", "+00:00"))
        if datetime.now(timezone.utc) > expire_dt:
            return {"success": False, "message": "เวลาการใช้งานหมดอายุแล้ว"}
    except Exception:
        return {"success": False, "message": "รูปแบบวันที่ไม่ถูกต้อง"}

    # HWID Binding
    reg_hwid = user.get("hwid")
    if not reg_hwid or reg_hwid in ["EMPTY", "UNKNOWN_DEVICE"]:
        supabase.table("users").update({"hwid": req.hwid}).eq("username", req.username).execute()
    elif reg_hwid != req.hwid:
        return {"success": False, "message": "บัญชีนี้ผูกไว้กับเครื่องอื่นแล้ว"}

    # Dynamic Session Token Generation
    session_token = secrets.token_hex(32)
    supabase.table("users").update({"session_token": session_token}).eq("username", req.username).execute()
    
    return {
        "success": True,
        "message": "เข้าสู่ระบบสำเร็จ",
        "session_token": session_token,
        "expire_date": user.get("expire_date")
    }

@app.post("/api/heartbeat")
def heartbeat(req: HeartbeatRequest, x_session_token: str = Header(None)):
    """Heartbeat สั้นลง รับ Token ผ่าน Header เพื่อความปลอดภัย"""
    if not supabase or not x_session_token:
        raise HTTPException(status_code=401, detail="Unauthorized")

    res = supabase.table("users").select("expire_date", "hwid", "session_token").eq("username", req.username).execute()
    if not res.data:
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    user = res.data[0]
    if user.get("hwid") != req.hwid or user.get("session_token") != x_session_token:
        raise HTTPException(status_code=401, detail="Unauthorized Target")
        
    expire_str = user.get("expire_date")
    if not expire_str:
        raise HTTPException(status_code=401, detail="Expired")

    try:
        expire_dt = datetime.fromisoformat(expire_str.replace("Z", "+00:00"))
        if datetime.now(timezone.utc) > expire_dt:
            raise HTTPException(status_code=401, detail="Expired")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid Expiry")

    # ส่ง Signature ยืนยันความถูกต้องกลับไป
    sync_sig = hashlib.sha256(f"{req.username}:{x_session_token}:{datetime.now(timezone.utc).minute}".encode()).hexdigest()
    return {"status": "alive", "sync_sig": sync_sig}

@app.post("/api/redeem")
def redeem_key(req: RedeemRequest):
    if not supabase:
        raise HTTPException(status_code=500, detail="Database connection error")

    user_res = supabase.table("users").select("expire_date").eq("username", req.username).execute()
    if not user_res.data:
        return {"success": False, "message": "ไม่พบ Username นี้"}

    key_res = supabase.table("license_keys").select("*").eq("key_code", req.key_code).eq("is_used", False).execute()
    if not key_res.data:
        return {"success": False, "message": "Serial Key ไม่ถูกต้อง หรือถูกใช้ไปแล้ว"}

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

    supabase.table("users").update({"expire_date": new_expire.isoformat()}).eq("username", req.username).execute()
    supabase.table("license_keys").update({"is_used": True, "used_by": req.username}).eq("key_code", req.key_code).execute()

    return {"success": True, "message": f"เติม Key สำเร็จ! เพิ่มวันใช้งาน {days_to_add} วัน"}
