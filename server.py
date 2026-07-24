import os
import hashlib
from datetime import datetime, timedelta, timezone
from fastapi import FastAPI, Header, HTTPException
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

class RegisterRequest(BaseModel):
    username: str
    password: str

class RedeemRequest(BaseModel):
    username: str
    key_code: str

# --- 1. สมัครสมาชิก ---
@app.post("/api/register")
def register(req: RegisterRequest):
    if not supabase:
        raise HTTPException(status_code=500, detail="Database error")

    check = (
        supabase.table("users")
        .select("username")
        .eq("username", req.username)
        .execute()
    )
    if check.data:
        return {"success": False, "message": "ชื่อผู้ใช้นี้ถูกใช้งานแล้ว!"}

    default_expire = datetime.now(timezone.utc)

    supabase.table("users").insert(
        {
            "username": req.username,
            "password_hash": hash_password(req.password),
            "hwid": "",
            "expire_date": default_expire.isoformat(),
        }
    ).execute()
    return {"success": True, "message": "สมัครสมาชิกสำเร็จ!"}

# --- 2. ล็อกอิน ---
@app.post("/api/login")
def login(req: LoginRequest):
    if not supabase:
        raise HTTPException(status_code=500, detail="Database error")

    # === ระบบตรวจสอบ EXE Hash ===
    expected_hash = EXPECTED_EXE_HASH.strip().lower()
    client_hash = req.exe_hash.strip().lower()

    print(f"=== HASH DEBUG ===")
    print(f"Server EXPECTED: [{expected_hash}] (Length: {len(expected_hash)})")
    print(f"Client RECEIVED: [{client_hash}] (Length: {len(client_hash)})")
    print(f"==================")

    # ตรวจสอบ Hash (อนุญาต dev_mode_no_hash สำหรับช่วงพัฒนา)
    if expected_hash and client_hash != expected_hash and client_hash != "dev_mode_no_hash":
        return {
            "success": False, 
            "message": "ตรวจพบการดัดแปลงไฟล์โปรแกรม หรือใช้เวอร์ชันเก่า กรุณาดาวน์โหลดใหม่!"
        }

    res = (
        supabase.table("users")
        .select("password_hash", "expire_date", "hwid")
        .eq("username", req.username)
        .execute()
    )
    if not res.data:
        return {"success": False, "message": "ไม่พบชื่อผู้ใช้นี้!"}

    user = res.data[0]

    if user["password_hash"] != hash_password(req.password):
        return {"success": False, "message": "รหัสผ่านไม่ถูกต้อง!"}

    expire_str = user.get("expire_date")
    if expire_str:
        try:
            expire_dt = datetime.fromisoformat(
                expire_str.replace("Z", "+00:00")
            )
            if datetime.now(timezone.utc) > expire_dt:
                return {
                    "success": False,
                    "message": "ระยะเวลาการใช้งานของคุณหมดอายุแล้ว!",
                }
        except Exception:
            pass

    reg_hwid = user.get("hwid")
    if not reg_hwid or reg_hwid == "EMPTY":
        supabase.table("users").update({"hwid": req.hwid}).eq(
            "username", req.username
        ).execute()
    elif reg_hwid != req.hwid:
        return {
            "success": False,
            "message": "บัญชีนี้ถูกผูกไว้กับเครื่องอื่นแล้ว!",
        }

    return {
        "success": True,
        "message": "เข้าสู่ระบบสำเร็จ!",
        "expire_date": user.get("expire_date"),
    }

# --- 3. เติมคีย์ ---
@app.post("/api/redeem")
def redeem(req: RedeemRequest):
    if not supabase:
        raise HTTPException(status_code=500, detail="Database error")

    key_res = (
        supabase.table("license_keys")
        .select("*")
        .eq("key_code", req.key_code)
        .eq("is_used", False)
        .execute()
    )

    if not key_res.data:
        return {
            "success": False,
            "message": "Key ไม่ถูกต้อง หรือถูกใช้งานไปแล้ว",
        }

    user_res = (
        supabase.table("users")
        .select("expire_date")
        .eq("username", req.username)
        .execute()
    )

    if not user_res.data:
        return {"success": False, "message": "ไม่พบผู้ใช้นี้ในระบบ"}

    key_info = key_res.data[0]
    raw_days = key_info.get("days") or key_info.get("duration_days", 1)
    try:
        duration_days = int(raw_days)
    except (ValueError, TypeError):
        duration_days = 1

    now = datetime.now(timezone.utc)
    current_expire_str = user_res.data[0].get("expire_date")

    base_date = now
    if current_expire_str:
        try:
            current_expire = datetime.fromisoformat(
                current_expire_str.replace("Z", "+00:00")
            )
            if current_expire > now:
                base_date = current_expire
        except Exception:
            pass

    new_expire = base_date + timedelta(days=duration_days)

    supabase.table("users").update({"expire_date": new_expire.isoformat()}).eq(
        "username", req.username
    ).execute()

    supabase.table("license_keys").update(
        {"is_used": True, "used_by": req.username}
    ).eq("key_code", req.key_code).execute()

    return {
        "success": True,
        "message": f"เติม Key สำเร็จ! เพิ่มวันใช้งาน {duration_days} วัน",
    }
