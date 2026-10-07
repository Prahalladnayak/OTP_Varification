from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import redis.asyncio as redis


app = FastAPI()


# Redis connection
redis_client = redis.Redis(
    host="localhost",
    port=6379,
    decode_responses=True
)


class OTPRequest(BaseModel):
    phone: str
    otp: str


@app.post("/verify-otp")
async def verify_otp(data: OTPRequest):

    phone = data.phone
    submitted_otp = data.otp

    # Redis keys
    otp_key = f"otp:{phone}"
    attempts_key = f"attempts:{phone}"
    verified_key = f"verified:{phone}"

    # 1. Check if phone is already verified
    verified = await redis_client.get(verified_key)

    if verified == "true":
        return {
            "success": True,
            "message": "Phone number is already verified"
        }

    # 2. Get current incorrect attempts
    attempts = await redis_client.get(attempts_key)

    if attempts is None:
        attempts = 0
    else:
        attempts = int(attempts)

    # 3. Check maximum attempts
    if attempts >= 3:
        raise HTTPException(
            status_code=429,
            detail="Maximum OTP attempts exceeded"
        )

    # 4. Fetch stored OTP
    stored_otp = await redis_client.get(otp_key)

    if stored_otp is None:
        raise HTTPException(
            status_code=400,
            detail="OTP not found or expired"
        )

    # 5. Compare submitted OTP with stored OTP
    if submitted_otp == stored_otp:

        # 6. Mark phone as verified
        await redis_client.set(
            verified_key,
            "true"
        )

        return {
            "success": True,
            "message": "Phone number verified successfully"
        }

    # 7. Wrong OTP → increase attempt count
    new_attempts = await redis_client.incr(attempts_key)

    # 8. Set expiration for attempts
    await redis_client.expire(
        attempts_key,
        300
    )

    remaining_attempts = 3 - new_attempts

    # 9. Maximum attempts reached
    if new_attempts >= 3:
        raise HTTPException(
            status_code=429,
            detail="Maximum OTP attempts exceeded"
        )

    # 10. Return invalid OTP
    raise HTTPException(
        status_code=400,
        detail=f"Invalid OTP. {remaining_attempts} attempts remaining"
    )