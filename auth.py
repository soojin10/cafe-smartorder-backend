import os
import re
import smtplib
import random
import string
import logging
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from typing import Dict, Optional, Any
from pydantic import BaseModel
from models import User

from loguru import logger
from dotenv import load_dotenv
from fastapi import HTTPException, Depends, status, Request
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session
from sqlalchemy import func, exists
import base64
from email.utils import formatdate

load_dotenv()

# 로깅 설정
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# 환경 변수 로드 및 검증
EMAIL_HOST = os.getenv("EMAIL_HOST", "smtp.gmail.com")
EMAIL_PORT = int(os.getenv("EMAIL_PORT", "587"))
EMAIL_HOST_USER = os.getenv("EMAIL_HOST_USER")
EMAIL_HOST_PASSWORD = os.getenv("EMAIL_HOST_PASSWORD")

if not all([EMAIL_HOST_USER, EMAIL_HOST_PASSWORD]):
    raise ValueError("이메일 설정이 올바르지 않습니다. 환경 변수를 확인하세요.")

# 비밀번호 해싱
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT 설정
SECRET_KEY = "your-secret-key-here"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = None  # 만료 시간 제거

# OAuth2 설정
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


# JWT 토 데이터 모델
class TokenData(BaseModel):
    username: Optional[str] = None
    email: Optional[str] = None

# 해싱된 비밀번호와 입력된 비밀번호가 일치하는지 확인
def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

#비밀번호 해싱
def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

# 이메일 중복확인
def check_email_exists(db: Session, email: str) -> bool:
    try:
        # 필요한 필드만 조회
        user = db.query(
            User.id,
            User.email
        ).filter(User.email == email).first()
        return user is not None
    except Exception as e:
        logger.error(f"이메일 중복 확인 중 오류 발생: {str(e)}")
        raise e

# 비밀번호가 정책을 준수하지 확인
def validate_password(password: str) -> bool:
    if len(password) < 8:
        return False
    if not re.search(r"\d", password):
        return False
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False
    return True

def generate_verification_code() -> str:
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))

#사용자에게 인증 이메일을 전송
def connect() -> smtplib.SMTP:
    try:
        # SMTP 서버에 연결
        server = smtplib.SMTP(EMAIL_HOST, EMAIL_PORT)
        server.ehlo()  # 서버에 인사
        server.starttls()  # TLS 보안 연결 시작
        server.ehlo()  # TLS 연결 후 다시 인사
        server.login(EMAIL_HOST_USER, EMAIL_HOST_PASSWORD)  # 로그인
        return server
    except smtplib.SMTPAuthenticationError as e:
        logger.error(f"SMTP Authentication Error: {e}")
        raise HTTPException(status_code=500, detail="Authentication failed with SMTP server")
    except smtplib.SMTPConnectError as e:
        logger.error(f"SMTP Connection Error: {e}")
        raise HTTPException(status_code=500, detail="Failed to connect to SMTP server")
    except Exception as e:
        logger.error(f"SMTP server connection failed: {e}")
        raise HTTPException(status_code=500, detail="Failed to connect to SMTP server")


def send_verification_email(email: str, verification_code: str, is_update: bool = False) -> None:
    try:
        # 이메일 내용 구성
        html_content = f"""
안녕하세요, EarlyOrder입니다.<br><br>

{'이메일 변경' if is_update else '회원가입'}을 완료하기 위해 아래의 인증 코드를 입력해주세요.<br><br>

<div style="font-size: 16px;">인증코드: 
    <span style="font-size: 24px; font-weight: bold; color: #000; background-color: #ffffff; padding: 10px; border-radius: 5px; display: inline-block; letter-spacing: 2px;">
        {verification_code}
    </span>
</div><br><br>

감사합니다.
"""
        
        # 이메일 메시지 생성
        msg = MIMEText(html_content, 'html', 'utf-8')
        msg['Subject'] = "EarlyOrder 이메일 인증"
        msg['From'] = "★EarlyOrder★"
        msg['To'] = email
        
        # SMTP 서버 연결 및 이메일 전송
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login(EMAIL_HOST_USER, EMAIL_HOST_PASSWORD)
            smtp.sendmail(EMAIL_HOST_USER, email, msg.as_string())
            
        logger.info(f"이메일 전송 성공: {email}")
            
    except Exception as e:
        logger.error(f"""
이메일 전송 실패:
- 수신자: {email}
- 에러: {str(e)}
- SMTP 설정:
  HOST: {EMAIL_HOST}
  PORT: 465
  USER: {EMAIL_HOST_USER}
""")
        raise HTTPException(
            status_code=500,
            detail=f"이메일 전송 중 오류가 발생했습니다: {str(e)}"
        )

# 사용자, 관리자 등록
def register_user(db: Session, email: str, password: str, username: str = "", is_admin: bool = False):
    try:
        hashed_password = get_password_hash(password)
        verification_code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
        auto_login_token = ''.join(random.choices(string.ascii_letters + string.digits, k=64))
        
        # is_admin 값을 정수형으로 변환
        is_admin_value = 1 if is_admin else 0
        
        new_user = User(
            email=email,
            username=username,
            hashed_password=hashed_password,
            is_active=True,
            is_admin=is_admin_value,
            verification_code=verification_code,
            is_verified=False,
            auto_login_token=auto_login_token
        )
        
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
        
        # 인증 이메일 전송
        try:
            send_verification_email(email, verification_code)
            logger.info(f"인증 이메일 전송 완료: {email}")
        except Exception as email_error:
            logger.error(f"인증 이메일 전송 실패: {str(email_error)}")
            pass

        return {
            "success": True,
            "message": "회원가입이 완료되었습니다.",
            "verification_code": verification_code,
            "is_admin": is_admin_value
        }
    except Exception as e:
        db.rollback()
        logger.error(f"회원가입 중 오류 발생: {str(e)}")
        raise e

# 이메일 검증
def verify_email(db: Session, email: str, verification_code: str) -> Dict[str, Any]:
    logger.info(f"Verifying email: {email} with code: {verification_code}")
    
    # User 테이블에 이메일로 사용자 찾기
    user = db.query(User).filter(User.email == email).first()
    
    if not user:
        logger.error(f"No user found with email: {email}")
        raise HTTPException(status_code=404, detail="사용자를 찾을 수 없습니다.")
    
    if user.verification_code != verification_code:
        logger.error(f"Verification code mismatch for email: {email}")
        raise HTTPException(status_code=400, detail="잘못된 인증 코드입니다.")
    
    # 인증 성공 시 사용자 상태 업데이트
    user.is_verified = True
    user.verification_code = None  # 인증 완료 후 코드 삭제
    db.commit()
    
    logger.info(f"Email verification successful for: {email}")
    return {"message": "이메일 인증이 성공적으로 완료되었습니다."}

# JWT 액세스 토큰 생성
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    
    # expires_delta가 None이면 만료 시간을 설정하지 않음
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
        to_encode.update({"exp": expire})
    
    # user_id가 이미 있다면 그대로 사용, 없다면 sub에서 가져오기
    if "user_id" not in to_encode and "sub" in to_encode:
        to_encode["user_id"] = to_encode["sub"]
    
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# JWT 토큰 검증하고 현재 사용자 반환
def get_current_user(db: Session, token: str) -> User:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("user_id")
        
        if user_id is None:
            raise HTTPException(status_code=401, detail="유효하지 않은 토큰입니다")
            
        # 문자열로 된 user_id를 정수로 변환
        try:
            user_id = int(user_id)
        except ValueError:
            raise HTTPException(status_code=401, detail="유효하지 않은 사용자입니다")
            
        user = db.query(User).filter(User.id == user_id).first()
        if user is None:
            raise HTTPException(status_code=404, detail="사용자를 찾을 수 없습니다")
            
        return user
        
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="토큰이 만료되었습니다")
    except jwt.JWTError as e:
        raise HTTPException(status_code=401, detail="인증할 수 없습니다")

def authenticate_user(db: Session, email: str, password: str) -> Dict[str, Any]:
    try:
        # 사용자 조회
        user = db.query(User).filter(User.email == email).first()
        
        # 이메일과 비밀번호가 모두 틀린 경우
        if not user:
            logger.error(f"User not found: {email}")
            raise HTTPException(
                status_code=404,  # 404로 변경
                detail="등록되지 않은 정보입니다"
            )

        # 비밀번호만 틀린 경우
        if not verify_password(password, user.hashed_password):
            logger.error(f"Invalid password for user: {email}")
            raise HTTPException(
                status_code=401,
                detail="이메일 또는 비밀번호가 올바르지 않습니다"
            )

        # 큰 생성
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={
                "user_id": str(user.id),  # 문자열로 변환
                "email": user.email,
                "is_admin": user.is_admin
            },
            expires_delta=access_token_expires
        )

        return {
            "access_token": access_token,
            "token_type": "bearer",
            "is_admin": user.is_admin,
            "username": user.username,
            "email": user.email,
            "id": user.id
        }

    except Exception as e:
        logger.error(f"Authentication error: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="인증 처리 중 오류가 발생했습니다"
        )

def create_auto_login_token(user_id: int) -> str:
    return jwt.encode(
        {"user_id": user_id, "type": "auto_login"},
        SECRET_KEY,
        algorithm=ALGORITHM
    )

def verify_auto_login_token(token: str) -> Optional[int]:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("type") != "auto_login":
            return None
        return payload.get("user_id")
    except JWTError:
        return None

def generate_auto_login_token() -> str:
    return ''.join(random.choices(string.ascii_letters + string.digits, k=64))

def set_auto_login_token(db: Session, user_id: int) -> str:
    token = generate_auto_login_token()
    user = db.query(User).filter(User.id == user_id).first()
    if user:
        user.auto_login_token = token
        db.commit()
        return token
    return None

def verify_auto_login_token(db: Session, token: str) -> Optional[User]:
    return db.query(User).filter(User.auto_login_token == token).first()

async def verify_token(request: Request):
    token = request.headers.get("Authorization")
    if not token or not token.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="인증되지 않은 사용자입니다.")
    return token.split(" ")[1]

# 공통 응답 포맷 함수
def create_response(success: bool, message: str, data: Any = None):
    return {
        "success": success,
        "message": message,
        "data": data
    }

def generate_random_password():
    # 최문 소문자, 숫자, 특수문자 정의
    lowercase = string.ascii_lowercase
    digits = string.digits
    special = "!@#$%^&*"
    
    # 각 카테고리에서 최소 1개씩 선택 (3자리)
    password = [
        random.choice(lowercase),    # 소문자 1개
        random.choice(digits),       # 숫자 1개
        random.choice(special)       # 특수문자 1개
    ]
    
    # 나머지 7자리를 모든 문자에서 랜덤 선택 (총 10자리)
    all_characters = lowercase + digits + special
    password.extend(random.choice(all_characters) for _ in range(7))
    
    # 문자열 순서를 랜덤하게 섞기
    random.shuffle(password)
    
    return ''.join(password)

def send_reset_password_email(email: str, new_password: str) -> None:
    try:
        message_text = f"""
        안녕하세요, EarlyOrder입니다.
        
        임시 비밀번호가 발급되었습니다:
        {new_password}
        
        보안을 위해 로그인 후 비밀번호를 변경해주세요.
        """
        
        message = MIMEText(message_text)
        message['Subject'] = "EarlyOrder 비밀번호 재설정"
        message['From'] = EMAIL_HOST_USER
        message['To'] = email

        server = smtplib.SMTP(EMAIL_HOST, EMAIL_PORT)
        server.starttls()
        server.login(EMAIL_HOST_USER, EMAIL_HOST_PASSWORD)
        server.send_message(message)
        server.quit()
        
    except Exception as e:
        logger.error(f"Failed to send reset password email: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to send reset password email")

def decode_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired"
        )
    except jwt.JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials"
        )

def authenticate_admin(db: Session, email: str, password: str) -> Dict[str, Any]:
    try:
        # 사용자 조회
        user = db.query(User).filter(User.email == email).first()
        
        # 사용자가 없는 경우
        if not user:
            logger.error(f"Admin not found: {email}")
            raise HTTPException(
                status_code=404,
                detail="등록되지 않은 관리자입니다"
            )

        # 관리자가 아닌 경우
        if not user.is_admin:
            logger.error(f"Non-admin user attempted login: {email}")
            raise HTTPException(
                status_code=403,
                detail="관리자 권한이 없습니다"
            )

        # 비밀번호 확인
        if not verify_password(password, user.hashed_password):
            logger.error(f"Invalid password for admin: {email}")
            raise HTTPException(
                status_code=401,
                detail="이메일 또는 비밀번호가 올바르지 않습니다"
            )

        # 토큰 생성
        access_token = create_access_token(
            data={
                "user_id": str(user.id),
                "email": user.email,
                "is_admin": user.is_admin
            }
        )

        return {
            "access_token": access_token,
            "token_type": "bearer",
            "is_admin": user.is_admin,
            "username": user.username,
            "email": user.email,
            "id": user.id
        }

    except HTTPException as he:
        raise he
    except Exception as e:
        logger.error(f"Admin authentication error: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="관리자 인증 처리 중 오류가 발생합니다"
        )