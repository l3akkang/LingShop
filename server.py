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
# ตัวแปรสำหรับเช็ก Hash ของไฟล์ .exe (ดึงจาก .env)
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
    exe_hash: str  # รับค่า Hash จากฝั่ง Client

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

    # สมัครใหม่ ตั้งให้หมดอายุทันที (ต้องเติมคีย์ถึงจะใช้งานได้)
    default_expire = datetime.now(timezone.utc)

    supabase.table("users").insert(
        {
            "username": req.username,
            "password_hash": hash_password(req.password), # บันทึกรหัสผ่านที่ Hash แล้ว
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

    # === ระบบตรวจสอบ EXE Hash (แบบเข้มงวด) ===
    expected_hash = EXPECTED_EXE_HASH.strip().lower()
    client_hash = req.exe_hash.strip().lower()

    # เช็กว่าเซิร์ฟเวอร์ตั้งค่า Hash ไว้หรือไม่
    if not expected_hash:
        return {
            "success": False,
            "message": "ระบบขัดข้อง: เซิร์ฟเวอร์ยังไม่ได้ตั้งค่า EXPECTED_EXE_HASH ใน .env"
        }

    # บังคับเช็ก Hash แบบตรงเป๊ะ
    if client_hash != expected_hash:
        return {
            "success": False, 
            "message": "ตรวจพบการดัดแปลงไฟล์โปรแกรม หรือใช้เวอร์ชันเก่า กรุณาดาวน์โหลดใหม่!"
        }
    # ==========================================

    res = (
        supabase.table("users")
        .select("password_hash", "expire_date", "hwid")
        .eq("username", req.username)
        .execute()
    )
    if not res.data:
        return {"success": False, "message": "ไม่พบชื่อผู้ใช้นี้!"}

    user = res.data[0]

    # เช็กว่ารหัสผ่านตรงไหม
    if user["password_hash"] != hash_password(req.password):
        return {"success": False, "message": "รหัสผ่านไม่ถูกต้อง!"}

    # เช็กวันหมดอายุ
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

    # บันทึก HWID ใหม่ หรือเช็ก HWID
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

    key_info = key_res.data[0]
    # รองรับการดึงฟิลด์ 'days' หรือ 'duration_days' พร้อมแปลงเป็น int เพื่อป้องกัน Error
    raw_days = key_info.get("days") or key_info.get("duration_days", 1)
    try:
        duration_days = int(raw_days)
    except (ValueError, TypeError):
        duration_days = 1

    new_expire = datetime.now(timezone.utc) + timedelta(days=duration_days)
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
