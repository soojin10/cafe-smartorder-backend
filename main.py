import sys
import os
import aiohttp
import random
import string
from email.mime.text import MIMEText
import json
from datetime import datetime, timedelta
import smtplib
import pytz  # 시간대 처리를 위한 라이브러리
from sqlalchemy import and_  # 이 부분 추가
from sqlalchemy import text  # 상단에 추가

# 상위 디렉토리를 Python 경로에 추가하여 모듈을 import할 수 있게 함
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database import SessionLocal
from models import Menu
import models
import logging
import uvicorn
import python_multipart
from fastapi import FastAPI, Body, Depends, Request, HTTPException, Form, status, WebSocket, WebSocketDisconnect, APIRouter, UploadFile, File
from fastapi.security import OAuth2PasswordBearer, HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from typing import List, Optional, Dict, Any
from geopy.distance import geodesic
from pydantic import BaseModel
from sqlalchemy import exists

# schemas에서 필요한 클래스들을 명시적으로 import
from schemas import (
    UserLogin,  # UserLogin을 명시적으로 import
    MenuItem,
    UserCreate,
    VerificationRequest,
    EmailRequest,
    PaymentCreate
)

import auth, crud, models, schemas, shutil
from database import engine, get_db
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
import websocket_server
import mysql.connector
from mysql.connector import Error
from fastapi.staticfiles import StaticFiles
from schemas import MenuItem
from jose import JWTError, jwt
from fastapi import HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from contextlib import asynccontextmanager
import base64
import requests
import asyncio

load_dotenv()

EMAIL_HOST = "smtp.gmail.com"
EMAIL_PORT = 465
EMAIL_HOST_USER = os.getenv("EMAIL_HOST_USER")
EMAIL_HOST_PASSWORD = os.getenv("EMAIL_HOST_PASSWORD")

# 토스페이먼츠 설정
TOSS_SECRET_KEY = os.getenv("TOSS_PAYMENTS_SECRET_KEY")
TOSS_CLIENT_KEY = os.getenv("TOSS_PAYMENTS_CLIENT_KEY")
TOSS_SUCCESS_URL = os.getenv("TOSS_PAYMENTS_SUCCESS_URL")
TOSS_FAIL_URL = os.getenv("TOSS_PAYMENTS_FAIL_URL")
TOSS_WEBHOOK_SECRET = os.getenv("TOSS_PAYMENTS_WEBHOOK_SECRET")

# Basic Auth 인코딩
TOSS_ENCODED_SECRET_KEY = base64.b64encode(f"{TOSS_SECRET_KEY}:".encode()).decode()

# 로깅 설정
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# 데이터베이스 테이블 생성
models.Base.metadata.create_all(bind=engine)

# main.py 상단에 라우터 추가
router = APIRouter()

# 기존 app = FastAPI() 아래에 추가
app = FastAPI()
app.include_router(router, prefix="/api")
app.mount("/earlyorder/web", StaticFiles(directory="/var/www/html/earlyorder/web"), name="web")

# 상단에 security 정의 추가
security = HTTPBearer()

# on_event를 lifespan으로 변경
@asynccontextmanager
async def lifespan(app: FastAPI):
    # 시작 시 실행
    routes = [{"path": route.path, "name": route.name} for route in app.routes]
    logger.info(f"Registered routes: {routes}")
    yield
    # 종료 시 실행

# FastAPI 인스턴스 생성 시 lifespan 추가
app = FastAPI(lifespan=lifespan)

# CORS 설정 확인
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://211.253.26.214:8000",  # 메인 서버
        "http://211.253.26.214:3000",  # 토스페이먼츠 서버
        "earlyorder://payment",        # 앱 스킴
        "*"  # 개발 중에는 모든 origin 허용
    ],  # 실제 운영 환경에서는 구체적인 도메인 지정
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
# Jinja2 템플릿 엔진 설정
templates = Jinja2Templates(directory="templates")
# OAuth2 설정
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# 요청 모델 추가
class EmailRequest(BaseModel):
    email: str

# ----- 루트 경로 (로그인 페이지로 리다이렉트) -----
@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    return RedirectResponse("/login_page")

# ----- 회원가입 -----
@app.post("/register")
async def register(request: Request, db: Session = Depends(get_db)):
    try:
        data = await request.json()
        email = data.get("email")
        password = data.get("password")
        username = data.get("username", "")
        
        logger.info(f"""
회원가입 상세 정보:
- 이메일: {email}
- 사용자명: {username}
- 요청 데이터: {data}
""")

        # 이메일 중복 체크
        existing_user = db.query(models.User).filter(models.User.email == email).first()
        if existing_user:
            return JSONResponse(
                status_code=400,
                content={
                    "success": False,
                    "message": "이미 등록된 이메일 주소입니다."
                }
            )

        # 일반 사용자 회원가입 처리 (is_admin=False)
        result = auth.register_user(db, email, password, username, is_admin=False)
        
        return JSONResponse(content=result)

    except Exception as e:
        logger.error(f"회원가입 중 오류 발생: {str(e)}")
        return JSONResponse(
            status_code=500,
            content={
                "success": False,
                "message": f"회원가입 처리 중 오류가 발생했습니다: {str(e)}"
            }
        )

# 관리자 회원가입
@app.post("/admin/register")
async def register_admin(request: Request, db: Session = Depends(get_db)):
    try:
        data = await request.json()
        email = data.get("email")
        password = data.get("password")
        username = data.get("username", "")
        
        logger.info(f"""
        관리자 회원가입 상세 정보:
        - 이메일: {email}
        - 사용자명: {username}
        - 요청 데이터: {data}
        """)

        # 이메일 중복 체크
        existing_user = db.query(models.User).filter(models.User.email == email).first()
        if existing_user:
            return JSONResponse(
                status_code=400,
                content={
                    "success": False,
                    "message": "이미 등록된 이메일 주소입니다."
                }
            )

        # 관리자 회원가입 처리 (is_admin=True)
        result = auth.register_user(db, email, password, username, is_admin=True)
        
        return JSONResponse(content=result)

    except Exception as e:
        logger.error(f"관리자 회원가입 중 오류 발생: {str(e)}")
        return JSONResponse(
            status_code=500,
            content={
                "success": False,
                "message": f"회원가입 처리 중 오류가 발생했습니다: {str(e)}"
            }
        )

# --- 인증코드 ---
@app.post("/verify-code", response_class=JSONResponse)
async def verify_code(email: str = Form(...), code: str = Form(...), db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.email == email).first()
    if not user:
        raise HTTPException(status_code=400, detail="Invalid email")
    if user.verification_code != code:
        raise HTTPException(status_code=400, detail="Invalid verification code")
    if user.is_verified:
        return {"message": "Email already verified"}

    user.is_verified = True
    db.commit()
    return {"message": "Email verified successfully"}

# ----- 로그인 -----
@app.post("/login")
async def login(request: Request, db: Session = Depends(get_db)):
    try:
        data = await request.json()
        email = data.get("email")
        password = data.get("password")
        
        if not email or not password:
            raise HTTPException(
                status_code=400,
                detail="Email and password are required"
            )
            
        # 사용자 인증
        result = auth.authenticate_user(db, email, password)
        logger.info(f"Login successful for user: {email}")
        logger.info(f"Generated token: {result['access_token']}")  # 디버깅용
        
        return JSONResponse(
            content={
                "success": True,
                "access_token": result["access_token"],
                "token_type": "bearer",
                "is_admin": result["is_admin"],
                "username": result["username"],
                "email": result["email"],
                "id": result["id"]
            }
        )
        
    except HTTPException as e:
        logger.error(f"Login error: {str(e)}")
        raise e
    except Exception as e:
        logger.error(f"Unexpected error during login: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=str(e)
        )

# ----- main 페이지 엔드포인트 -----
@app.get("/main", response_class=HTMLResponse)
async def main_page(request: Request):
    return templates.TemplateResponse("main.html", {"request": request})

# ----- 이메일 확인 페이지 -----
@app.get("/verify-email", response_class=HTMLResponse)
async def verify_email_form(request: Request, error: Optional[str] = None):
    return templates.TemplateResponse(
        "verify_email.html", {"request": request, "error": error}
    )

# ----- 이메일 인증-----
@app.post("/verify-email", response_model=Dict[str, Any])
async def verify_email_code(
    verification_request: schemas.VerificationRequest,
    db: Session = Depends(get_db)
):
    try:
        # 임시 저장된 이메일로 사용자 찾기
        temp_email = verification_request.temp_email if hasattr(verification_request, 'temp_email') else verification_request.email
        user = db.query(models.User).filter(models.User.email == verification_request.email).first()
        
        if not user:
            raise HTTPException(
                status_code=404,
                detail="사용자를 찾을 수 없습니다."
            )

        # 인증 코드 확인
        if user.verification_code != verification_request.verification_code:
            raise HTTPException(
                status_code=400,
                detail="잘못된 인증 코드입니다."
            )

        # 이메일 업데이트 및 인증 상태 변경
        user.is_verified = True
        if hasattr(verification_request, 'temp_email'):
            user.email = verification_request.temp_email
        
        db.commit()

        return JSONResponse(
            content={
                "success": True,
                "message": "이메일 인증이 성공적으로 완료되었습니다."
            },
            headers={"Content-Type": "application/json; charset=utf-8"}
        )
    except HTTPException as e:
        return JSONResponse(
            content={
                "success": False,
                "message": str(e.detail)
            },
            headers={"Content-Type": "application/json; charset=utf-8"}
        )

# ----- 이메일 중복 확인 -----
@app.post("/auth/check-email", response_class=JSONResponse)
async def check_email(request: Request, db: Session = Depends(get_db)):
    try:
        data = await request.json()
        email = data.get("email")

        if not email:
            return JSONResponse(
                status_code=400,
                content={"available": False, "message": "이메일이 제공되지 않습니다."}
            )

        email_exists = auth.check_email_exists(db, email)
        return JSONResponse(
            content={
                "success": True,
                "message": "사용 가능한 이메일입니다." if not email_exists else "이미 사용중인 이메일입니다.",
                "available": not email_exists
            }
        )
    except Exception as e:
        logger.error(f"이일 중 확인 중 오류 : {str(e)}")
        return JSONResponse(
            status_code=500,
            content={"available": False, "message": "서버 오류가 발생했습니다."}
        )

# ----- 사용자 목록 조 (테스트용, 나중에 제거 가능) -----
@app.get("/users/", response_model=List[schemas.User])
def read_users(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    users = crud.get_users(db, skip=skip, limit=limit)
    return users

# ----- 관리자 목록 조회 (테스트용, 나중에 제거 가능) -----
@app.get("/admins/", response_model=List[schemas.User])
def read_admins(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    admins = crud.get_admins(db, skip=skip, limit=limit)
    return admins

# ----- 특정 사용자 정보 조회 (본인 정보 확인 등에 활 능) -----
@app.get("/user/me")
async def get_current_user_info(request: Request, db: Session = Depends(get_db)):
    try:
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            raise HTTPException(
                status_code=401,
                detail="인증되지 않은 사용자입니다."
            )
        
        token = auth_header.split(" ")[1]
        user = auth.get_current_user(db, token)
        
        return JSONResponse(
            status_code=200,
            content={
                "success": True,
                "data": {
                    "id": user.id,
                    "email": user.email,
                    "username": user.username,
                    "is_admin": user.is_admin,
                    "is_verified": user.is_verified
                }
            }
        )
    except HTTPException as e:
        logger.error(f"사용자 정보 조회 중 오류 발생: {e.status_code}: {e.detail}")
        raise e
    except Exception as e:
        logger.error(f"사용자 정보 조회 중 오류 발생: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="서버 오류가 발생했습니다."
        )

@app.post("/check-location")
async def check_location(request: Request):
    data = await request.json()
    user_latitude = data.get("latitude")
    user_longitude = data.get("longitude")

    # 주문 가능 지역 정보 (양주시)
    available_regions = [
        {"name": "양주시", "latitude": 37.7833, "longitude": 127.0417, "radius": 20},  # 반경 20km
    ]

    for region in available_regions:
        distance = geodesic((user_latitude, user_longitude), (region["latitude"], region["longitude"])).km
        if distance <= region["radius"]:
            return {"available": True}

    return {"available": False}

@app.post("/sendVerificationCode", response_class=JSONResponse)
async def send_verification_code(email_request: EmailRequest, db: Session = Depends(get_db)):
    try:
        # 현재 사용자 찾기 (기존 이메일로)
        user = db.query(models.User).filter(models.User.email == email_request.email).first()
        if user:
            # 인증 코드 생성 및 저장
            verification_code = auth.generate_verification_code()
            user.verification_code = verification_code
            db.commit()
        
        # auth.py의 send_verification_email 함수 호출
        auth.send_verification_email(email_request.email, verification_code)
        
        return JSONResponse(
            status_code=200,
            content={
                "success": True,
                "message": "인증 코드가 이메일로 발송되었습니다."
            }
        )
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={
                "success": False,
                "message": "인증 코드 전송에 실패했습니다.",
                "error": str(e)
            }
        )

@app.post("/admin/login")
async def admin_login(request: Request, db: Session = Depends(get_db)):
    try:
        data = await request.json()
        email = data.get("email")
        password = data.get("password")
        
        if not email or not password:
            raise HTTPException(
                status_code=400,
                detail="이메일과 비밀번호를 모두 입력해주세요"
            )
            
        # auth.py의 authenticate_admin 함수 호출
        result = auth.authenticate_admin(db, email, password)
        logger.info(f"Admin login successful for user: {email}")
        
        return JSONResponse(content=result)
        
    except HTTPException as e:
        logger.error(f"Admin login error: {str(e)}")
        raise e
    except Exception as e:
        logger.error(f"Unexpected error during admin login: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=str(e)
        )

@app.get("/api/menu", response_class=JSONResponse)
async def get_menu_list(db: Session = Depends(get_db)):
    try:
        menu_items = db.query(models.Menu).all()
        
        return JSONResponse(
            status_code=200,
            content={
                "success": True,
                "data": [
                    {
                        "id": item.id,
                        "name": item.name,
                        "price": item.price,
                        "category": item.category,
                        "image_url": item.image_url,
                        "is_available": item.is_available
                    } for item in menu_items
                ]
            }
        )
    except Exception as e:
        logger.error(f"메뉴 목록 조회 중 오류 발생: {str(e)}")
        return JSONResponse(
            status_code=500,
            content={
                "success": False,
                "message": "메뉴 목록 조회 중 오류가 발생했습니다."
            }
        )

@app.post("/auth/login", response_class=JSONResponse)
async def login(request: Request, login_data: schemas.UserLogin, db: Session = Depends(get_db)):
    try:
        user = db.query(
            models.User.id,
            models.User.email,
            models.User.username,
            models.User.hashed_password,
            models.User.is_admin,
            models.User.is_active,
            models.User.is_verified
        ).filter(models.User.email == login_data.email).first()
        
        # 사용자가 존재하지 않는 경우
        if not user:
            return JSONResponse(
                status_code=401,
                content={
                    "success": False,
                    "message": "등록되지 않은 정보입니다."
                }
            )
        
        # 비밀번호 확인
        if not auth.verify_password(login_data.password, user.hashed_password):
            return JSONResponse(
                status_code=401,
                content={
                    "success": False,
                    "message": "이메일 또는 비밀번호가 잘못되었습니다."
                }
            )
            
        if not user.is_verified:
            return JSONResponse(
                status_code=401,
                content={
                    "success": False,
                    "message": "이메일 인증 필요합니다."
                }
            )

        # access_token 생성 시 문자열로 환하여 전달
        access_token = auth.create_access_token(
            data={
                "sub": str(user.email),  # 문자열로 변환
                "user_id": str(user.id)  # 사용자 ID도 문자열로 변환
            }
        )
        
        return JSONResponse(
            content={
                "success": True,
                "message": "로그인 성공",
                "access_token": access_token,
                "is_admin": user.is_admin,
                "username": user.username,
                "email": user.email
            }
        )
    except Exception as e:
        logger.error(f"로그인 처리 중 오류 발생: {str(e)}")
        return JSONResponse(
            status_code=500,
            content={
                "success": False,
                "message": "서버 오류가 발생했습니다."
            }
        )


# 메뉴 CRUD A
@app.put("/api/menu/update/{menu_id}")
async def update_menu(
    menu_id: int, 
    menu_update: dict = Body(...), 
    db: Session = Depends(get_db)
):
    try:
        logger.info(f"Updating menu {menu_id} with data: {menu_update}")  # 디버깅용 로그 추가
        
        db_menu = db.query(models.Menu).filter(models.Menu.id == menu_id).first()
        if not db_menu:
            logger.error(f"Menu with id {menu_id} not found")  # 에러 로그 추가
            raise HTTPException(
                status_code=404, 
                detail={"success": False, "message": "메뉴를 찾을 수 없습니다"}
            )
            
        # 업데이트할 필드 검증
        update_fields = {}
        if 'name' in menu_update and menu_update['name']:
            update_fields['name'] = menu_update['name']
        if 'price' in menu_update and menu_update['price']:
            update_fields['price'] = int(menu_update['price'])
        if 'is_available' in menu_update:
            update_fields['is_available'] = bool(menu_update['is_available'])
            
        # 필드 업데이트
        for field, value in update_fields.items():
            setattr(db_menu, field, value)
            
        db.commit()
        db.refresh(db_menu)
        
        logger.info(f"Menu {menu_id} updated successfully")  # 성공 로그 추가
        
        return JSONResponse(
            status_code=200,
            content={
                "success": True, 
                "message": "메뉴가 수정되었습니다",
                "data": {
                    "id": db_menu.id,
                    "name": db_menu.name,
                    "price": db_menu.price,
                    "is_available": db_menu.is_available,
                    "category": db_menu.category,
                    "image_url": db_menu.image_url
                }
            }
        )
    except HTTPException as e:
        db.rollback()
        raise e
    except Exception as e:
        logger.error(f"Error updating menu: {str(e)}")  # 에러 로그 추가
        db.rollback()
        raise HTTPException(
            status_code=500, 
            detail={"success": False, "message": f"메뉴 수정 중 오류가 발생했습니다: {str(e)}"}
        )

@app.delete("/api/menu/delete/{menu_id}")
async def delete_menu(menu_id: int, db: Session = Depends(get_db)):
    try:
        logger.info(f"Deleting menu with ID: {menu_id}")
        db_menu = db.query(models.Menu).filter(models.Menu.id == menu_id).first()
        
        if not db_menu:
            return JSONResponse(
                status_code=404,
                content={
                    "success": False,
                    "message": "메뉴를 찾을 수 없습니다."
                }
            )
            
        db.delete(db_menu)
        db.commit()
        
        return JSONResponse(
            status_code=200,
            content={
                "success": True,
                "message": "메뉴가 성공적으로 삭제되었습니다."
            }
        )
            
    except Exception as e:
        logger.error(f"메뉴 삭제 중 오류 발생: {str(e)}")
        db.rollback()
        return JSONResponse(
            status_code=500,
            content={
                "success": False,
                "message": "메뉴 삭제 중 오류가 발생했습니다."
            }
        )

# 메뉴 생성 API 수정 (이미지 업로드)
@app.post("/api/menu/create")
async def create_menu(
    menu_data: dict = Body(...),
    db: Session = Depends(get_db)
):
    try:
        logger.info(f"Received menu data: {menu_data}")
        
        # 필요한 필드만 추출
        filtered_data = {
            'name': menu_data['name'],
            'price': int(menu_data['price']),
            'category': menu_data['category'],
            'image_url': menu_data.get('image_url'),
            'is_available': menu_data.get('is_available', True)
        }
        
        # 카테고리 검증
        valid_categories = [
            "COFFEE", "LATTE", "TEA", "SMOOTHE", 
            "SHAKE/FRAPPE", "BEVERAGE",
            "BAKERY/DESSERT"
        ]
        
        if filtered_data['category'] not in valid_categories:
            raise HTTPException(
                status_code=400,
                detail="유효하지 않은 카테고리입니다"
            )
            
        new_menu = models.Menu(**filtered_data)
        
        db.add(new_menu)
        db.commit()
        db.refresh(new_menu)
        
        return {
            "success": True,
            "message": "메뉴가 추가되었습니다",
            "data": {
                "id": new_menu.id,
                "name": new_menu.name,
                "price": new_menu.price,
                "category": new_menu.category,
                "image_url": new_menu.image_url,
                "is_available": new_menu.is_available
            }
        }
    except HTTPException as e:
        db.rollback()
        raise e
    except Exception as e:
        logger.error(f"Error creating menu: {str(e)}")
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/orders/create")
async def create_order(request: Request, db: Session = Depends(get_db)):
    try:
        current_user = await get_current_user(request, db)
        order_data = await request.json()
        
        logger.info(f"받은 주문 데이터: {order_data}")
        
        created_orders = []
        order_time = datetime.now(pytz.timezone('Asia/Seoul'))
        
        items = order_data.get("items", [])
        if not items:
            items = [order_data]
        
        for item in items:
            # 메뉴 ID 또는 메뉴 이름으로 메뉴 찾기
            menu = None
            if menu_id := (item.get("menuId") or item.get("menu_id")):
                menu = db.query(models.Menu).filter(models.Menu.id == menu_id).first()
            elif menu_name := (item.get("menuName") or item.get("menu_name")):
                menu = db.query(models.Menu).filter(models.Menu.name == menu_name).first()
            
            if not menu:
                raise HTTPException(
                    status_code=404, 
                    detail=f"메뉴를 찾을 수 없습니다: {menu_name or menu_id}"
                )
            
            unit_price = item.get("unitPrice")  # 클라이언트에서 보낸 개별 가격
            total_price = item.get("price") or item.get("total_price") or menu.price
            quantity = item.get("quantity", 1)
            
            new_order = models.Order(
                user_id=current_user.id,
                user_name=current_user.username,
                user_email=current_user.email,
                menu_id=menu.id,
                unit_price=unit_price,  # 클라이언트에서 받은 개별 가격 사용
                total_price=total_price,
                quantity=quantity,
                status="준비중",
                order_time=order_time,
                hot_ice_option=item.get("hotIceOption") or item.get("hot_ice_option"),
                size=item.get("size"),
                shot_quantity=item.get("shotQuantity") or item.get("shot_quantity", 0),
                hazelnut_quantity=item.get("hazelnutQuantity") or item.get("hazelnut_quantity", 0),
                tapioca_quantity=item.get("tapiocaQuantity") or item.get("tapioca_quantity", 0),
                decaf_quantity=item.get("decafQuantity") or item.get("decaf_quantity", 0),
                vanilla_quantity=item.get("vanillaQuantity") or item.get("vanilla_quantity", 0),
                whipping_quantity=item.get("whippingQuantity") or item.get("whipping_quantity", 0),
                icecream_quantity=item.get("iceCreamQuantity") or item.get("icecream_quantity", 0)
            )
            
            db.add(new_order)
            db.flush()
            
            created_orders.append({
                "order_id": new_order.id,
                "menu_name": menu.name,
                "total_price": new_order.total_price,
                "order_time": new_order.order_time.strftime("%Y-%m-%d %H:%M:%S"),
                "status": new_order.status
            })
        
        db.commit()
        
        return JSONResponse(
            status_code=200,
            content={
                "success": True,
                "message": "주문이 성공적으로 생성되었습니다",
                "data": created_orders
            }
        )
        
    except Exception as e:
        db.rollback()
        logger.error(f"주문 생성 중 오류 발생: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

    
@app.get("/api/orders/pending")
async def get_pending_orders(db: Session = Depends(get_db)):
    try:
        # 대기 중이고 결제가 완료된 주문 가져오기 (order_time으로 오름차순 정렬)
        pending_orders = db.query(models.Order).filter(
            and_(
                models.Order.is_completed == False,
                models.Order.payment_status == 1
            )
        ).order_by(models.Order.order_time.asc()).all()  # desc()를 asc()로 변경

        # 주문을 그룹화하여 카운트
        pending_groups = {}
        for order in pending_orders:
            group_key = f"{order.user_id}_{order.order_time}"
            if group_key not in pending_groups:
                pending_groups[group_key] = []
            pending_groups[group_key].append(order)

        # 완료된 주문 그룹 카운트 (정산되지 않은 주문만)
        today = datetime.now(pytz.timezone('Asia/Seoul')).date()
        completed_orders = db.query(models.Order).filter(
            and_(
                models.Order.is_completed == True,
                models.Order.completed_time >= today,
                models.Order.is_settled == False
            )
        ).all()

        completed_groups = {}
        for order in completed_orders:
            group_key = f"{order.user_id}_{order.order_time}"
            if group_key not in completed_groups:
                completed_groups[group_key] = []
            completed_groups[group_key].append(order)

        # 주문 데이터 처리
        orders_data = []
        for group_key, orders in pending_groups.items():
            for order in orders:
                menu = db.query(models.Menu).filter(models.Menu.id == order.menu_id).first()
                if menu:
                    options = []
                    if order.hot_ice_option:
                        options.append(order.hot_ice_option)
                    if order.shot_quantity > 0:
                        options.append(f"샷 추가 {order.shot_quantity}개 (+500원)")
                    if order.hazelnut_quantity > 0:
                        options.append(f"헤이즐럿 시럽 {order.hazelnut_quantity}개 (+500원)")
                    if order.vanilla_quantity > 0:
                        options.append(f"바닐라 시럽 {order.vanilla_quantity}개 (+500원)")
                    if order.tapioca_quantity > 0:
                        options.append(f"타피오카 {order.tapioca_quantity}개 (+1000원)")
                    if order.whipping_quantity > 0:
                        options.append(f"휘핑크림 {order.whipping_quantity}개 (+800원)")
                    if order.decaf_quantity > 0:
                        options.append(f"디카페인 {order.decaf_quantity}개 (+800원)")
                    if order.icecream_quantity > 0:
                        options.append(f"아이스크림 {order.icecream_quantity}개 (+1500원)")

                    order_data = {
                        "id": order.id,
                        "user_id": order.user_id,
                        "user_name": order.user_name,
                        "user_email": order.user_email,
                        "menu_name": menu.name,
                        "menu_price": menu.price,
                        "quantity": order.quantity,
                        "total_amount": order.total_price,
                        "order_time": order.order_time.isoformat(),
                        "options": options,
                        "items": [{
                            "menu_name": menu.name,
                            "quantity": order.quantity,
                            "menu_price": menu.price,
                            "options": options
                        }]
                    }
                    orders_data.append(order_data)

        return {
            "success": True,
            "orders": orders_data,
            "stats": {
                "pending_count": len(pending_groups),
                "completed_count": len(completed_groups)
            }
        }
    except Exception as e:
        logger.error(f"Error in get_pending_orders: {str(e)}")
        db.rollback()
        raise HTTPException(
            status_code=500, 
            detail=f"Internal server error: {str(e)}"
        )

@app.get("/api/mypage")
async def get_mypage(request: Request, db: Session = Depends(get_db)):
    try:
        # 토큰에 사용자 정보 가져오기 
        token = request.headers.get("Authorization")
        if not token:
            return JSONResponse(
                status_code=401,
                content={
                    "success": False,
                    "message": "인증되지 않은 사용자입니다."
                }
            )
            
        # Bearer 토큰에서 실제 토큰 값 추출
        token = token.split(" ")[1]
        current_user = auth.get_current_user(db, token)
        
        if not current_user:
            return JSONResponse(
                status_code=401,
                content={
                    "success": False,
                    "message": "유효지 않은 토큰입니다."
                }
            )
            
        # 사용자 주문 내역 조회
        user_orders = db.query(models.Order).filter(models.Order.user_id == current_user.id).all()
        
        return JSONResponse(
            status_code=200,
            content={
                "success": True,
                "data": {
                    "user": {
                        "id": current_user.id,
                        "email": current_user.email,
                        "username": current_user.username
                    },
                    "orders": [
                        {
                            "id": order.id,
                            "total_price": order.total_price,
                            "status": order.status,
                            "created_at": order.created_at.isoformat()
                        } for order in user_orders
                    ]
                }
            }
        )
    
    except Exception as e:
        logger.error(f"마이페이지 조회 중 오류 발생: {str(e)}")
        return JSONResponse(
            status_code=500,
            content={
                "success": False,
                "message": "마이페이지 조회 중 오류가 발생했니다."
            }
        )

@app.post("/auth/logout")
async def logout(request: Request, db: Session = Depends(get_db)):
    try:
        token = request.headers.get("Authorization")
        if not token:
            return JSONResponse(
                status_code=401,
                content={"success": False, "message": "인증되지 않은 사용자니다."}
            )
            
        token = token.split(" ")[1]
        # 토큰 무효화 로직 추가
        
        return JSONResponse(
            status_code=200,
            content={"success": True, "message": "로그아웃되었습니다."}
        )
    except Exception as e:
        logger.error(f"로그아웃 중 오류 발생: {str(e)}")
        return JSONResponse(
            status_code=500,
            content={"success": False, "message": "로그아웃 중 오류가 발생했습니다."}
        )

@app.get("/api/test-db")
async def test_db_connection(db: Session = Depends(get_db)):
    try:
        # DB 연결 테스트
        result = db.execute("SELECT 1").fetchone()
        return JSONResponse(
            status_code=200,
            content={"success": True, "message": "DB 연결 성공"}
        )
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"success": False, "message": f"DB 연결 실패: {str(e)}"}
        )

@app.post("/api/auth/auto-login")
async def auto_login(request: Request, db: Session = Depends(get_db)):
    try:
        token = request.headers.get("Authorization")
        if not token or not token.startswith("Bearer "):
            return JSONResponse(
                status_code=401,
                content={"success": False, "message": "인되지 않은 사용자입니다."}
            )
            
        token = token.split(" ")[1]
        user = auth.verify_auto_login_token(db, token)
            
        if not user:
            return JSONResponse(
                status_code=401,
                content={"success": False, "message": "유효하지 않은 토큰입니다."}
            )
            
        access_token = auth.create_access_token(
            data={"sub": user.email, "is_admin": user.is_admin}
        )
        
        return JSONResponse(
            status_code=200,
            content={
                "success": True,
                "access_token": access_token,
                "is_admin": user.is_admin,
                "username": user.username,
                "email": user.email
            }
        )
        
    except Exception as e:
        logger.error(f"자동 로그인 리 중 오류 발생: {str(e)}")
        return JSONResponse(
            status_code=500,
            content={"success": False, "message": "자동 로그인 처리 중 오류가 발생했니다."}
        )

@app.post("/update_user")
async def update_user_info(request: Request, db: Session = Depends(get_db)):
    try:
        data = await request.json()
        new_name = data.get("username")  # 클라이언트에서 보내는 키 이름과 일치하도록
        
        auth_header = request.headers.get("Authorization")
        logger.info(f"Auth header: {auth_header}")
        
        if not auth_header or not auth_header.startswith("Bearer "):
            return JSONResponse(
                status_code=401,
                content={"success": False, "message": "인증지 않은 사용자입니."}
            )
            
        token = auth_header.split(" ")[1]
        logger.info(f"Token: {token}")
        
        try:
            payload = jwt.decode(token, auth.SECRET_KEY, algorithms=[auth.ALGORITHM])
            user_id = payload.get("user_id")
            logger.info(f"Decoded user_id: {user_id}")
            
            if not user_id:
                return JSONResponse(
                    status_code=401,
                    content={"success": False, "message": "유효하지 않은 토큰입니다."}
                )
            
            user = db.query(models.User).filter(models.User.id == user_id).first()
            if not user:
                return JSONResponse(
                    status_code=404,
                    content={"success": False, "message": "사용자를 찾을 수 없습니다."}
                )
            
            if new_name:
                user.username = new_name
            
            db.commit()
            
            return JSONResponse(
                content={
                    "success": True,
                    "message": "사용자 정보가 업데트되었습니다",
                    "data": {
                        "username": user.username,
                        "email": user.email
                    }
                }
            )
            
        except jwt.JWTError as e:
            logger.error(f"JWT 디코딩 오류: {str(e)}")
            return JSONResponse(
                status_code=401,
                content={"success": False, "message": "인증 토큰이 유효하지 않니다."}
            )
            
    except Exception as e:
        logger.error(f"사용자 정보 업데트 중 오류: {str(e)}")
        return JSONResponse(
            status_code=500,
            content={"success": False, "message": f"서버 오류가 생습니다: {str(e)}"}
        )

@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    return JSONResponse(
        status_code=exc.status_code,
        content={"success": False, "message": str(exc.detail)}
    )

@app.post("/api/upload-image")
async def upload_image(file: UploadFile):
    try:
        # 파일 기 제한 (예: 5MB)
        MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB in bytes
        content = await file.read()
        
        if len(content) > MAX_FILE_SIZE:
            raise HTTPException(status_code=400, detail="파일 크기가 너무 큽니다 (최대 5MB)")

        # imgur API 클라이언트 설정
        async with aiohttp.ClientSession() as session:
            headers = {
                'Authorization': 'Client-ID eac6d927c2294e4'  # Client-ID 접두 추가
            }
            
            # 이미지 데이터 준비
            data = aiohttp.FormData()
            data.add_field('image', 
                         content,
                         filename=file.filename,
                         content_type=file.content_type)
            
            # imgur API 호출
            try:
                async with session.post(
                    'https://api.imgur.com/3/image',
                    data=data,
                    headers=headers,
                    timeout=30  
                ) as response:
                    if response.status != 200:
                        error_detail = await response.text()
                        logger.error(f"Imgur API 오류: {error_detail}")
                        raise HTTPException(status_code=500, detail="이미지 업로드 실패")
                    
                    result = await response.json()
                    if not result.get('success'):
                        logger.error(f"Imgur API 응답 오류: {result}")
                        raise HTTPException(status_code=500, detail="이미지 업로드 실패")
                        
                    image_url = result['data']['link']
                    logger.info(f"업로된 이미지 URL: {image_url}")
                    return {"success": True, "url": image_url}
                    
            except aiohttp.ClientError as e:
                logger.error(f"Imgur API 통신 오류: {str(e)}")
                raise HTTPException(status_code=500, detail="이미지 서버 통신 오류")
                
    except Exception as e:
        logger.error(f"이미지 로 중 오류: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))
    
    finally:
        # 파일 버퍼 정리
        await file.close()

@app.post("/change-password")
async def change_password(request: Request, db: Session = Depends(get_db)):
    try:
        data = await request.json()
        current_password = data.get("current_password")
        new_password = data.get("new_password")
        
        auth_header = request.headers.get("Authorization")
        
        if not auth_header or not auth_header.startswith("Bearer "):
            return JSONResponse(
                status_code=401,
                content={"success": False, "message": "인증되지 않은 사용자니다."}
            )
            
        token = auth_header.split(" ")[1]
        
        try:
            # 토큰 만료 시간을 검증하지 않도록 수정
            payload = jwt.decode(token, auth.SECRET_KEY, algorithms=[auth.ALGORITHM], options={"verify_exp": False})
            user_id = payload.get("user_id")
            
            if not user_id:
                return JSONResponse(
                    status_code=401,
                    content={"success": False, "message": "유효하지 않은 토큰입니다."}
                )
            
            user = db.query(models.User).filter(models.User.id == user_id).first()
            if not user:
                return JSONResponse(
                    status_code=404,
                    content={"success": False, "message": "사용자를 찾을 수 없습니다."}
                )
            
            if not auth.verify_password(current_password, user.hashed_password):
                return JSONResponse(
                    status_code=400,
                    content={"success": False, "message": "현재 비밀번호가 일치하지 않습니다."}
                )
            
            user.hashed_password = auth.get_password_hash(new_password)
            db.commit()
            
            return JSONResponse(
                status_code=200,
                content={"success": True, "message": "비밀번호가 변경되었습니다."}
            )
            
        except jwt.JWTError as e:
            logger.error(f"토큰 디코딩 오류: {str(e)}")
            return JSONResponse(
                status_code=401,
                content={"success": False, "message": "인증 토큰 유효하지 않습니다."}
            )
            
    except Exception as e:
        logger.error(f"비밀번 변경 중 오류 발생: {str(e)}")
        return JSONResponse(
            status_code=500,
            content={"success": False, "message": "서버 오류가 발생했습니다."}
        )

@app.post("/find-password")
async def find_password(request: Request, db: Session = Depends(get_db)):
    try:
        data = await request.json()
        email = data.get("email")
        
        # 사용자 확인
        user = db.query(models.User).filter(models.User.email == email).first()
        if not user:
            return JSONResponse(
                status_code=404,
                content={
                    "success": False,
                    "message": "존재하지 않는 이메일입니다."
                }
            )
        
        # 임시 비밀번호 생성
        temp_password = auth.generate_random_password()
        
        # 비밀번호 해시화 및 DB 업데이트
        user.hashed_password = auth.get_password_hash(temp_password)
        db.commit()
        
        try:
            # 이메일 발송
            auth.send_reset_password_email(email, temp_password)
            
            return JSONResponse(
                status_code=200,
                content={
                    "success": True,
                    "message": "임시 비밀번호가 이메일로 발송되었습니다."
                }
            )
            
        except Exception as e:
            logger.error(f"이메일 발송 실패: {str(e)}")
            db.rollback()  # 이메일 발송 실패 시 DB 롤백
            return JSONResponse(
                status_code=500,
                content={
                    "success": False,
                    "message": "이메일 발송에 실패습니다."
                }
            )
            
    except Exception as e:
        logger.error(f"비밀번호 찾기 중 오류 발생: {str(e)}")
        return JSONResponse(
            status_code=500,
            content={
                "success": False,
                "message": "서버 오류가 발생했습니다."
            }
        )

# HTTP Bearer 토큰 스키 설정
security = HTTPBearer()

@app.post("/verify_token")
async def verify_token_endpoint(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
):
    try:
        token = credentials.credentials
        user = auth.get_current_user(db, token)
        
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={
                "success": True,
                "data": {
                    "id": user.id,
                    "email": user.email,
                    "username": user.username,
                    "is_admin": user.is_admin,
                    "is_verified": user.is_verified
                }
            }
        )
        
    except HTTPException as he:
        if he.status_code == 401:
            return JSONResponse(
                status_code=he.status_code,
                content={
                    "success": False,
                    "message": "인증이 필요합니다. 다시 로그인해 주세요."
                }
            )
        raise he
    except Exception as e:
        logger.error(f"토큰 검증 중 오류 발생: {str(e)}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "success": False,
                "message": "서버 오류가 발생했습니다."
            }
        )

async def get_current_user(request: Request, db: Session = Depends(get_db)):
    try:
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            raise HTTPException(
                status_code=401,
                detail="인증되지 않은 사용자입니다."
            )
        
        token = auth_header.split(" ")[1]
        user = auth.get_current_user(db, token)
        return user
        
    except HTTPException as e:
        logger.error(f"사용자 정보 조회 중 오류 발생: {e.status_code}: {e.detail}")
        raise e
    except Exception as e:
        logger.error(f"사용자 정보 조회 중 오류 발생: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="서버 오류가 생습니다."
        )

@app.post("/delete_account")
async def delete_account(request: Request, db: Session = Depends(get_db)):
    try:
        current_user = await get_current_user(request, db)
        
        # 사용자와 관련된 모이터 삭제
        # 주문 삭제
        db.query(models.Order).filter(models.Order.user_id == current_user.id).delete()
        # 사용자 삭제
        db.query(models.User).filter(models.User.id == current_user.id).delete()
        
        db.commit()
        return {"success": True, "message": "계정이 성공적으로 삭제되었습니다."}
    except Exception as e:
        logger.error(f"Account deletion error: {str(e)}")
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))

@app.put("/api/orders/{order_id}/complete")
async def complete_order(order_id: int, db: Session = Depends(get_db)):
    try:
        # 주문 조회
        order = db.query(models.Order).filter(models.Order.id == order_id).first()
        if not order:
            raise HTTPException(status_code=404, detail="주문을 찾을 수 없습니다")

        if order.is_completed:
            raise HTTPException(status_code=400, detail="이미 완료된 주문입니다")

        # 현재 시간 설정
        current_time = datetime.now(pytz.timezone('Asia/Seoul'))
        
        # 같은 시간, 같은 사용자의 모든 주문 완료 처리
        related_orders = db.query(models.Order).filter(
            and_(
                models.Order.user_id == order.user_id,
                models.Order.order_time == order.order_time,
                models.Order.is_completed == False
            )
        ).all()

        try:
            for related_order in related_orders:
                related_order.is_completed = True
                related_order.completed_time = current_time
                related_order.is_settled = False
            db.commit()
        except Exception as db_error:
            db.rollback()
            logger.error(f"DB 업데이트 실패: {str(db_error)}")
            raise HTTPException(status_code=500, detail="주문 상태 업데이트 실패")

        try:
            # 대기 중인 주문 수 (그룹화된 주문 기준)
            pending_orders = db.query(models.Order).filter(
                and_(
                    models.Order.payment_status == 1,
                    models.Order.is_completed == False
                )
            ).all()

            # 완료된 주문 수 (그룹화된 주문 기준)
            completed_orders = db.query(models.Order).filter(
                and_(
                    models.Order.is_completed == True,
                    models.Order.completed_time >= current_time.date(),
                    models.Order.is_settled == False
                )
            ).all()

            # 주문을 사용자와 주문시간으로 그룹화
            pending_groups = {}
            for order in pending_orders:
                key = (order.user_id, order.order_time)
                if key not in pending_groups:
                    pending_groups[key] = []
                pending_groups[key].append(order)

            completed_groups = {}
            for order in completed_orders:
                key = (order.user_id, order.order_time)
                if key not in completed_groups:
                    completed_groups[key] = []
                completed_groups[key].append(order)

            return {
                "success": True,
                "message": "주문이 완료되었습니다",
                "stats": {
                    "pending_count": len(pending_groups),
                    "completed_count": len(completed_groups)
                }
            }
        except Exception as count_error:
            logger.error(f"통계 조회 실패: {str(count_error)}")
            raise HTTPException(status_code=500, detail="주문 통계 조회 실패")

    except HTTPException as http_error:
        raise http_error
    except Exception as e:
        logger.error(f"주문 취료 처리 중 오류 발생: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/api/orders/{order_id}/delete")
async def delete_order(order_id: int, db: Session = Depends(get_db)):
    try:
        # 주문 조회
        order = db.query(models.Order).filter(models.Order.id == order_id).first()
        if not order:
            raise HTTPException(status_code=404, detail="주문을 찾을 수 없습니다")
            
        # 같은 시간에 생성된 같은 사용자의 모든 주문 취소 처리
        related_orders = db.query(models.Order).filter(
            and_(
                models.Order.user_id == order.user_id,
                models.Order.order_time == order.order_time
            )
        ).all()

        try:
            current_time = datetime.now(pytz.timezone('Asia/Seoul'))
            
            # text()를 사용하여 SQL 쿼리 실행
            update_query = text("""
                UPDATE orders 
                SET status = '취소', 
                    is_completed = 2,
                    completed_time = :completed_time
                WHERE id = :order_id
            """)
            
            for related_order in related_orders:
                db.execute(
                    update_query,
                    {
                        'completed_time': current_time,
                        'order_id': related_order.id
                    }
                )
            db.commit()
            
            return JSONResponse(
                status_code=200,
                content={
                    "success": True,
                    "message": "주문이 취소되었습니다",
                    "status": "취소"
                }
            )
            
        except Exception as db_error:
            db.rollback()
            logger.error(f"주문 취소 중 DB 오류: {str(db_error)}")
            raise HTTPException(
                status_code=500,
                detail="주문 취소 중 오류가 발생했습니다."
            )

    except HTTPException as http_error:
        raise http_error
    except Exception as e:
        logger.error(f"주문 취소 중 오류 발생: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/orders/completed")
async def get_completed_orders(db: Session = Depends(get_db)):
    try:
        # 오늘 날짜 기준으로 완료되고(is_completed=True) 아직 정산되지 않은(closure=False) 주문만 조회
        today = datetime.now(pytz.timezone('Asia/Seoul')).date()
        completed_orders = db.query(models.Order).filter(
            and_(
                models.Order.is_completed == True,
                models.Order.closure == False,  # 정산되지 않은 주문만
                models.Order.completed_time >= today
            )
        ).all()
        
        orders_data = []
        for order in completed_orders:
            menu = db.query(models.Menu).filter(models.Menu.id == order.menu_id).first()
            if menu:
                orders_data.append({
                    "id": order.id,
                    "menu_name": menu.name,
                    "menu_price": menu.price,
                    "quantity": order.quantity,
                    "total_price": order.total_price,
                    "completed_time": order.completed_time,
                    "size": order.size,
                    "shot_quantity": order.shot_quantity,
                    "hazelnut_quantity": order.hazelnut_quantity,
                    "tapioca_quantity": order.tapioca_quantity,
                    "decaf_quantity": order.decaf_quantity,
                    "vanilla_quantity": order.vanilla_quantity,
                    "whipping_quantity": order.whipping_quantity,
                    "icecream_quantity": order.icecream_quantity,
                    "closure": order.closure
                })
        
        return {"success": True, "orders": orders_data}
        
    except Exception as e:
        logger.error(f"완료된 주문 조회 중 오류 발생: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/orders/reset")
async def reset_orders(db: Session = Depends(get_db)):
    try:
        # 완료된 주문들의 closure 값을 True로 변경
        today = datetime.now(pytz.timezone('Asia/Seoul')).date()
        completed_orders = db.query(models.Order).filter(
            and_(
                models.Order.is_completed == True,
                models.Order.completed_time >= today,
                models.Order.closure == False  # 아직 정산되지 않은 주문만
            )
        ).update({"closure": True, "is_settled": True}, synchronize_session=False)
        
        db.commit()
        return {"success": True, "message": "정산이 완료되었습니다"}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/cart")
async def get_cart_items(request: Request, db: Session = Depends(get_db)):
    try:
        current_user = await get_current_user(request, db)
        
        # 사용자의 장바구니 아이템 조회
        cart_items = db.query(models.Cart).filter(
            models.Cart.user_id == current_user.id
        ).all()
        
        cart_data = []
        for cart_item in cart_items:
            menu = cart_item.menu
            cart_data.append({
                "menuItem": {
                    "name": menu.name,
                    "price": menu.price,
                    "category": menu.category,
                    "imageUrl": menu.image_url,
                    "isAvailable": menu.is_available
                },
                "quantity": cart_item.quantity,
                "hotIceOption": cart_item.hot_ice_option,
                "size": cart_item.size,
                "shotQuantity": cart_item.shot_quantity,
                "hazelnutQuantity": cart_item.hazelnut_quantity,
                "tapiocaQuantity": cart_item.tapioca_quantity,
                "decafQuantity": cart_item.decaf_quantity,
                "vanillaQuantity": cart_item.vanilla_quantity,
                "whippingQuantity": cart_item.whipping_quantity,
                "iceCreamQuantity": cart_item.icecream_quantity
            })
        
        return JSONResponse(
            status_code=200,
            content={
                "success": True,
                "data": cart_data
            }
        )
    except Exception as e:
        logger.error(f"장바구니 조회 중 오류 발생: {str(e)}")
        return JSONResponse(
            status_code=500,
            content={
                "success": False,
                "message": str(e)
            }
        )

@app.post("/api/cart/create")
async def create_cart_order(request: Request, db: Session = Depends(get_db)):
    try:
        current_user = await get_current_user(request, db)
        data = await request.json()
        
        # 기존 장바구니 아이템 삭제
        db.query(models.Cart).filter(
            models.Cart.user_id == current_user.id
        ).delete()
        
        # 새로운 장바구니 아이템 추가
        items = data.get('items', [])
        for item_data in items:
            menu = db.query(models.Menu).filter(
                models.Menu.name == item_data['name']
            ).first()
            
            if not menu:
                return JSONResponse(
                    status_code=404,
                    content={
                        "success": False,
                        "message": "존재하지 않는 메뉴입니다.",
                        "data": None
                    }
                )
            
            cart_item = models.Cart(
                user_id=current_user.id,
                menu_id=menu.id,
                quantity=item_data['quantity'],
                hot_ice_option=item_data.get('hotIceOption'),
                size=item_data.get('size'),
                shot_quantity=item_data.get('shotQuantity', 0),
                hazelnut_quantity=item_data.get('hazelnutQuantity', 0),
                tapioca_quantity=item_data.get('tapiocaQuantity', 0),
                decaf_quantity=item_data.get('decafQuantity', 0),
                vanilla_quantity=item_data.get('vanillaQuantity', 0),
                whipping_quantity=item_data.get('whippingQuantity', 0),
                icecream_quantity=item_data.get('iceCreamQuantity', 0)
            )
            db.add(cart_item)
        
        db.commit()
        
        return JSONResponse(
            status_code=200,
            content={
                "success": True,
                "message": "장바구니가 업데이트되었습니다.",
                "data": None
            }
        )
        
    except Exception as e:
        logger.error(f"장바구니 업데이트 중 오류 발생: {str(e)}")
        db.rollback()
        return JSONResponse(
            status_code=500,
            content={
                "success": False,
                "message": str(e),
                "data": None
            }
        )

@app.get("/api/orders/current/{order_id}")
async def get_order_status(order_id: int, request: Request, db: Session = Depends(get_db)):
    try:
        current_user = await get_current_user(request, db)
        
        order = db.query(models.Order).filter(
            models.Order.id == order_id,
            models.Order.user_id == current_user.id
        ).first()
        
        if not order:
            raise HTTPException(status_code=404, detail="주문을 찾을 수 없습니다")
            
        # 같은 시간의 모든 주문 찾기
        orders = db.query(models.Order).filter(
            models.Order.user_id == current_user.id,
            models.Order.order_time == order.order_time
        ).all()
        
        if not orders:
            raise HTTPException(status_code=404, detail="주문을 찾을 수 없습니다")
        
        menu = db.query(models.Menu).filter(models.Menu.id == order.menu_id).first()
        
        # 주문 상태 결정 로직 수정
        if order.payment_status == 0:
            status = "대기중"
        elif order.payment_status == 1 and not order.is_completed:
            status = "준비중"
        elif order.payment_status == 1 and order.is_completed:
            status = "완료"
        
        order_list = []
        for order in orders:
            menu = db.query(models.Menu).filter(models.Menu.id == order.menu_id).first()
            
            # 주문 상태 결정
            if order.payment_status == 0:
                status = "대기중"
            elif order.payment_status == 1 and not order.is_completed:
                status = "준비중"
            elif order.payment_status == 1 and order.is_completed:
                status = "완료"
            
            order_list.append({
                "order_id": order.id,
                "menu_name": menu.name if menu else "알 수 없는 메뉴",
                "total_price": order.total_price,
                "order_time": order.order_time.strftime("%Y-%m-%d %H:%M:%S"),
                "status": status,
                "completed_time": order.completed_time.strftime("%Y-%m-%d %H:%M:%S") if order.completed_time else None,
                "options": {
                    "hot_ice": order.hot_ice_option,
                    "size": order.size,
                    "shot": order.shot_quantity,
                    "hazelnut": order.hazelnut_quantity,
                    "tapioca": order.tapioca_quantity,
                    "decaf": order.decaf_quantity,
                    "vanilla": order.vanilla_quantity,
                    "whipping": order.whipping_quantity,
                    "icecream": order.icecream_quantity
                }
            })
        
        return JSONResponse(
            status_code=200,
            content={
                "success": True,
                "message": "주문 상태 조회 성공",
                "data": order_list
            }
        )
        
    except Exception as e:
        logger.error(f"주문 상태 조회 중 오류 발생: {str(e)}")
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(status_code=500, detail=str(e))

    
@app.get("/api/orders/history")
async def get_order_history(request: Request, db: Session = Depends(get_db)):
    try:
        current_user = await get_current_user(request, db)
        
        # 사용자의 모든 주문 내역 조회
        orders = db.query(models.Order).filter(
            models.Order.user_id == current_user.id
        ).order_by(models.Order.order_time.desc()).all()
        
        order_history = []
        for order in orders:
            menu = db.query(models.Menu).filter(models.Menu.id == order.menu_id).first()
            
            # 주문 상태 결정
            if order.payment_status == 0:
                status = "대기중"
            elif order.payment_status == 1 and not order.is_completed:
                status = "준비중"
            elif order.payment_status == 1 and order.is_completed:
                status = "완료"
            
            order_history.append({
                "order_id": order.id,
                "menu_name": menu.name if menu else "알 수 없는 메뉴",
                "total_price": order.total_price,
                "unit_price": order.unit_price,  # 개별 가격 추가
                "quantity": order.quantity,  # 수량 추가
                "order_time": order.order_time.strftime("%Y-%m-%d %H:%M:%S"),
                "status": status,
                "completed_time": order.completed_time.strftime("%Y-%m-%d %H:%M:%S") if order.completed_time else None,
                "options": {
                    "hot_ice": order.hot_ice_option,
                    "size": order.size,
                    "shot": order.shot_quantity,
                    "hazelnut": order.hazelnut_quantity,
                    "tapioca": order.tapioca_quantity,
                    "decaf": order.decaf_quantity,
                    "vanilla": order.vanilla_quantity,
                    "whipping": order.whipping_quantity,
                    "icecream": order.icecream_quantity
                }

            })
        
        return JSONResponse(
            status_code=200,
            content={
                "success": True,
                "message": "주문 내역 조회 성공",
                "data": order_history
            }
        )
        
    except Exception as e:
        logger.error(f"주문 내역 조회 중 오류 발생: {str(e)}")
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/favorites/update")
async def update_favorite_status(request: Request, db: Session = Depends(get_db)):
    try:
        current_user = await get_current_user(request, db)
        data = await request.json()
        
        logger.info(f"Received favorite update request: {data}")
        
        menu_name = data.get("menuName")
        is_favorite = data.get("isFavorite")
        hot_ice_option = data.get("hotIceOption")
        size = data.get("size")
        price = data.get("price", 0)
        image_url = data.get("imageUrl")
        total_price = data.get("totalPrice", price)
        shot_quantity = data.get("shotQuantity", 0)
        hazelnut_quantity = data.get("hazelnutQuantity", 0)
        tapioca_quantity = data.get("tapiocaQuantity", 0)
        decaf_quantity = data.get("decafQuantity", 0)
        vanilla_quantity = data.get("vanillaQuantity", 0)
        whipping_quantity = data.get("whippingQuantity", 0)
        icecream_quantity = data.get("iceCreamQuantity", 0)
        
        # 메뉴 정보 조회
        menu = db.query(models.Menu).filter(models.Menu.name == menu_name).first()
        if not menu:
            raise HTTPException(status_code=404, detail="메뉴를 찾을 수 없습니다")
            
        if is_favorite:
            # 완전히 동일한 옵션을 가진 즐겨찾기 확인
            existing_favorite = db.query(models.Favorite).filter(
                models.Favorite.user_id == current_user.id,
                models.Favorite.menu_name == menu_name,
                models.Favorite.hot_ice_option == hot_ice_option,
                models.Favorite.size == size,
                models.Favorite.shot_quantity == shot_quantity,
                models.Favorite.hazelnut_quantity == hazelnut_quantity,
                models.Favorite.tapioca_quantity == tapioca_quantity,
                models.Favorite.decaf_quantity == decaf_quantity,
                models.Favorite.vanilla_quantity == vanilla_quantity,
                models.Favorite.whipping_quantity == whipping_quantity,
                models.Favorite.icecream_quantity == icecream_quantity
            ).first()
            
            if existing_favorite:
                # 완전히 동일한 옵션의 즐겨찾기가 이미 있으면 삭제
                db.delete(existing_favorite)
                logger.info(f"Deleted duplicate favorite: {existing_favorite.__dict__}")
            
            # 새로운 즐겨찾기 추가
            favorite = models.Favorite(
                user_id=current_user.id,
                menu_id=menu.id,
                menu_name=menu_name,
                price=price,
                image_url=image_url,
                total_price=total_price,
                hot_ice_option=hot_ice_option,
                size=size,
                shot_quantity=shot_quantity,
                hazelnut_quantity=hazelnut_quantity,
                tapioca_quantity=tapioca_quantity,
                decaf_quantity=decaf_quantity,
                vanilla_quantity=vanilla_quantity,
                whipping_quantity=whipping_quantity,
                icecream_quantity=icecream_quantity
            )
            db.add(favorite)
            logger.info(f"Added new favorite: {favorite.__dict__}")
                
        else:
            # 즐겨찾기 제거 시에도 모든 옵션을 확인하여 삭제
            db.query(models.Favorite).filter(
                models.Favorite.user_id == current_user.id,
                models.Favorite.menu_name == menu_name,
                models.Favorite.hot_ice_option == hot_ice_option,
                models.Favorite.size == size,
                models.Favorite.shot_quantity == shot_quantity,
                models.Favorite.hazelnut_quantity == hazelnut_quantity,
                models.Favorite.tapioca_quantity == tapioca_quantity,
                models.Favorite.decaf_quantity == decaf_quantity,
                models.Favorite.vanilla_quantity == vanilla_quantity,
                models.Favorite.whipping_quantity == whipping_quantity,
                models.Favorite.icecream_quantity == icecream_quantity
            ).delete()
            
        db.commit()
        return {"success": True, "message": "즐겨찾기가 업데이트되었습니다"}
        
    except Exception as e:
        logger.error(f"즐겨찾기 업데이트 중 오류 발생: {str(e)}")
        db.rollback()
        return JSONResponse(
            status_code=500,
            content={
                "success": False,
                "message": f"즐겨찾기 업데이트 중 오류가 발생했습니다: {str(e)}"
            }
        )

# 즐겨찾기 목록 조회 엔드포인트는 그대로 유지
@app.get("/api/favorites")
async def get_favorites(request: Request, db: Session = Depends(get_db)):
    try:
        current_user = await get_current_user(request, db)
        favorites = db.query(models.Favorite).filter(
            models.Favorite.user_id == current_user.id
        ).all()
        
        result = []
        for favorite in favorites:
            menu = db.query(models.Menu).filter(models.Menu.id == favorite.menu_id).first()
            base_price = menu.price if menu else favorite.price
            
            result.append({
                "menuName": favorite.menu_name,
                "price": base_price,
                "imageUrl": favorite.image_url,
                "hotIceOption": favorite.hot_ice_option,
                "size": favorite.size,
                "shotQuantity": favorite.shot_quantity,
                "hazelnutQuantity": favorite.hazelnut_quantity,
                "tapiocaQuantity": favorite.tapioca_quantity,
                "decafQuantity": favorite.decaf_quantity,
                "vanillaQuantity": favorite.vanilla_quantity,
                "whippingQuantity": favorite.whipping_quantity,
                "iceCreamQuantity": favorite.icecream_quantity,
                "totalPrice": favorite.total_price
            })
        
        return {
            "success": True,
            "data": result
        }
        
    except Exception as e:
        logger.error(f"즐겨찾기 목록 조회 중 오류 발생: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

# 이미지 저장 경로 설정
UPLOAD_DIR = "uploads/posters"
if not os.path.exists(UPLOAD_DIR):
    os.makedirs(UPLOAD_DIR)

# 포스터 업로드 API
@app.post("/api/posters/upload")
async def upload_poster(file: UploadFile, db: Session = Depends(get_db)):
    try:
        # 파일 크기 제한 (5MB)
        MAX_FILE_SIZE = 5 * 1024 * 1024
        content = await file.read()
        
        if len(content) > MAX_FILE_SIZE:
            raise HTTPException(status_code=400, detail="파일 크기가 너무 큽니다 (최대 5MB)")

        # imgur API 업로드
        async with aiohttp.ClientSession() as session:
            headers = {
                'Authorization': 'Client-ID eac6d927c2294e4'
            }
            
            data = aiohttp.FormData()
            data.add_field('image', 
                         content,
                         filename=file.filename,
                         content_type=file.content_type)
            
            async with session.post(
                'https://api.imgur.com/3/image',
                data=data,
                headers=headers,
                timeout=30
            ) as response:
                if response.status != 200:
                    error_detail = await response.text()
                    logger.error(f"Imgur API 오류: {error_detail}")
                    raise HTTPException(status_code=500, detail="이미지 업로드 실패")
                
                result = await response.json()
                if not result.get('success'):
                    logger.error(f"Imgur API 응답 오류: {result}")
                    raise HTTPException(status_code=500, detail="이미지 업로드 실패")
                    
                image_url = result['data']['link']
                
                # DB에 저장
                new_poster = models.Poster(
                    filename=file.filename,
                    image_url=image_url
                )
                db.add(new_poster)
                db.commit()
                db.refresh(new_poster)
                
                return {
                    "success": True,
                    "poster": {
                        "id": new_poster.id,
                        "filename": new_poster.filename,
                        "image_url": new_poster.image_url
                    }
                }
                
    except Exception as e:
        logger.error(f"포스터 업로드 중 오류: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        await file.close()

@app.get("/api/posters")
async def get_posters(db: Session = Depends(get_db)):
    try:
        posters = db.query(models.Poster).order_by(models.Poster.created_at.desc()).all()
        return {
            "success": True,
            "posters": [
                {
                    "id": poster.id,
                    "filename": poster.filename,
                    "image_url": poster.image_url,
                    "created_at": poster.created_at
                } for poster in posters
            ]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/api/posters/{poster_id}")
async def delete_poster(poster_id: int, db: Session = Depends(get_db)):
    try:
        poster = db.query(models.Poster).filter(models.Poster.id == poster_id).first()
        if not poster:
            raise HTTPException(status_code=404, detail="포스터를 찾을 수 없습니다")
        
        # 파일 삭제
        file_path = os.path.join(UPLOAD_DIR, poster.filename)
        if os.path.exists(file_path):
            os.remove(file_path)
        
        # DB에서 삭제
        db.delete(poster)
        db.commit()
        
        return {"success": True}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/payments/prepare")
async def prepare_payment(request: Request, db: Session = Depends(get_db)):
    try:
        # 1. Bearer 토큰으로 사용자 인증
        current_user = await get_current_user(request, db)
        data = await request.json()
        order_id = data.get("order_id")
        amount = data.get("amount")
        
        if not all([order_id, amount]):
            raise HTTPException(
                status_code=400,
                detail="주문 ID와 결제 금액이 필요합니다."
            )

        # 2. 주문 정보 확인
        order = db.query(models.Order).filter(
            models.Order.id == order_id,
            models.Order.user_id == current_user.id
        ).first()
        
        if not order:
            raise HTTPException(
                status_code=404,
                detail="주문을 찾을 수 없습니다."
            )

        # 3. 토스 페이먼츠 API 호출
        async with aiohttp.ClientSession() as session:
            payload = {
                "amount": int(amount),
                "orderId": str(order_id),  # 단순화된 주문 ID 사용
                "orderName": f"EarlyOrder #{order_id}",
                "successUrl": f"{os.getenv('APP_URL')}/api/payments/success",
                "failUrl": f"{os.getenv('APP_URL')}/api/payments/fail",
                "customerEmail": current_user.email,
                "customerName": current_user.username,
                "flowMode": "DEFAULT",  # DIRECT에서 DEFAULT로 변경
                "method": "카드"
            }
            
            headers = {
                "Authorization": f"Basic {TOSS_ENCODED_SECRET_KEY}",
                "Content-Type": "application/json"
            }
            
            async with session.post(
                "https://api.tosspayments.com/v1/payments",
                headers=headers,
                json=payload
            ) as response:
                result = await response.json()
                
                if response.status != 200:
                    error_msg = result.get("message", "결제 준비 중 오류가 발생했습니다.")
                    logger.error(f"토스 페이먼츠 API 에러: {error_msg}")
                    raise HTTPException(
                        status_code=response.status,
                        detail=error_msg
                    )
                
                # 결제창 URL 반환
                checkout_url = result.get("checkout", {}).get("url")
                if not checkout_url:
                    raise HTTPException(
                        status_code=500,
                        detail="결제창 URL을 받지 못했습니다."
                    )
                
                return {
                    "success": True,
                    "paymentKey": result.get("paymentKey"),
                    "orderName": payload["orderName"],
                    "amount": amount,
                    "checkoutUrl": checkout_url  # 결제창 URL 추가
                }
    except Exception as e:
        logger.error(f"결제 준비 중 오류 발생: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="결제 처리 중 오류가 발생했습니다."
        )

# 결제 성공 처리 엔드포인트
@app.get("/api/payments/success")
async def payment_success(
    paymentKey: str,
    orderId: str,
    amount: int,
    request: Request,  # Request 파라미터 추가
    db: Session = Depends(get_db)
):
    try:
        logger.info(f"""
결제 성공 요청:
- paymentKey: {paymentKey}
- orderId: {orderId}
- amount: {amount}
- URL: {request.url}
""")

        # 토스페이먼츠 결제 승인 요청
        async with aiohttp.ClientSession() as session:
            secret_key = os.getenv('TOSS_PAYMENTS_SECRET_KEY')
            if not secret_key:
                raise HTTPException(
                    status_code=500,
                    detail="토스페이먼츠 시크릿 키가 설정되지 않았습니다."
                )

            encoded_secret_key = base64.b64encode(secret_key.encode()).decode()
            headers = {
                "Authorization": f"Basic {encoded_secret_key}",
                "Content-Type": "application/json"
            }
            
            try:
                async with session.post(
                    f"https://api.tosspayments.com/v1/payments/{paymentKey}/confirm",
                    headers=headers,
                    json={
                        "orderId": orderId,
                        "amount": amount
                    },
                    timeout=30
                ) as response:
                    result = await response.json()
                    logger.info(f"토스페이먼츠 응답: {result}")

                    if response.status == 200:
                        # 기준이 되는 주문 조회
                        target_order = db.query(models.Order).filter(
                            models.Order.id == orderId
                        ).first()
                        
                        if target_order:
                            # 같은 시간에 같은 사용자가 주문한 모든 주문 찾기
                            group_orders = db.query(models.Order).filter(
                                models.Order.user_id == target_order.user_id,
                                models.Order.order_time == target_order.order_time
                            ).all()
                            
                            # 같은 시간에 같은 사용자가 주문한 모든 주문 완료 처리
                            for related_order in group_orders:
                                related_order.is_completed = True
                                related_order.completed_time = datetime.now()
                                related_order.is_settled = False
                            db.commit()
                            
                            # 성공 페이지로 리다이렉트 또는 JSON 응답
                            if "application/json" in request.headers.get("accept", ""):
                                return {
                                    "success": True,
                                    "message": "결제가 완료되었습니다",
                                    "orderId": orderId
                                }
                            else:
                                return RedirectResponse(
                                    url=f"/payment-success?orderId={orderId}",
                                    status_code=303
                                )
                        else:
                            logger.error(f"주문 {orderId}를 찾을 수 없음")
                            raise HTTPException(
                                status_code=404,
                                detail="주문을 찾을 수 없습니다"
                            )

            except asyncio.TimeoutError:
                logger.error("토스페이먼츠 API 타임아웃")
                raise HTTPException(
                    status_code=408,
                    detail="결제 서버 응답 시간 초과"
                )

    except HTTPException as he:
        logger.error(f"결제 처리 중 HTTP 에러: {str(he)}")
        raise he
    except Exception as e:
        logger.error(f"결제 처리 중 예외 발생: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="결제 처리 중 오류가 발생했습니다"
        )

@app.post("/api/payments/confirm")
async def confirm_payment(
    paymentKey: str,
    orderId: str,
    amount: int,
    request: Request,
    db: Session = Depends(get_db)
):
    try:
        logger.info(f"""
결제 확인 요청 받음:
- Payment Key: {paymentKey}
- Order ID: {orderId}
- Amount: {amount}
- Headers: {request.headers}
""")

        # 토큰 검증
        token = request.headers.get("Authorization")
        if not token:
            logger.error("인증 토큰 없음")
            raise HTTPException(status_code=401, detail="인증되지 않은 사용자입니다.")
        token = token.split(" ")[1]
        current_user = auth.get_current_user(db, token)
        logger.info(f"인증된 사용자: {current_user.email}")

        # 토스페이먼츠 결제 승인 API 호출
        async with aiohttp.ClientSession() as session:
            headers = {
                "Authorization": f"Basic {TOSS_ENCODED_SECRET_KEY}",
                "Content-Type": "application/json"
            }
            
            logger.info("토스페이먼츠 API 호출 시작")
            async with session.post(
                "https://api.tosspayments.com/v1/payments/confirm",
                headers=headers,
                json={
                    "paymentKey": paymentKey,
                    "orderId": orderId,
                    "amount": amount
                }
            ) as response:
                result = await response.json()
                logger.info(f"토스페이먼츠 API 응답: {result}")
                
                if response.status == 200:
                    logger.info("결제 승인 성공")
                    # 결제 정보 저장
                    payment_data = {
                        "order_id": orderId,
                        "payment_key": paymentKey,
                        "amount": amount,
                        "status": "DONE",
                        "payment_type": result.get("method", "카드"),
                        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    }
                    logger.info(f"저장할 결제 데이터: {payment_data}")
                    
                    try:
                        payment = crud.create_payment(db, payment_data)
                        logger.info(f"결제 정보 DB 저장 성공: {payment.__dict__}")
                    except Exception as db_error:
                        logger.error(f"결제 정보 DB 저장 실패: {str(db_error)}")
                        raise
                    
                    # 기준 주문 찾기
                    base_order = db.query(models.Order).filter(
                        models.Order.id == int(orderId)
                    ).first()
                    logger.info(f"기준 주문 조회: {base_order.__dict__ if base_order else 'Not found'}")
                    
                    if base_order:
                        # 같은 사용자의 같은 시간대 주문 찾기 (1초 이내)
                        related_orders = db.query(models.Order).filter(
                            and_(
                                models.Order.user_id == current_user.id,
                                models.Order.created_at >= base_order.created_at - timedelta(seconds=1),
                                models.Order.created_at <= base_order.created_at + timedelta(seconds=1)
                            )
                        ).all()
                        logger.info(f"관련 주문 수: {len(related_orders)}")
                        
                        # 모든 연관 주문 상태 업데이트
                        current_time = datetime.now()
                        for order in related_orders:
                            order.payment_status = 1  # 결제 완료
                            order.paid_at = current_time
                            logger.info(f"주문 상태 업데이트: Order ID {order.id}, Status: 결제완료")
                        
                        try:
                            db.commit()
                            logger.info("모든 관련 주문 상태 업데이트 완료")
                        except Exception as commit_error:
                            logger.error(f"주문 상태 업데이트 실패: {str(commit_error)}")
                            db.rollback()
                            raise
                    
                    return {
                        "success": True,
                        "payment": {
                            "order_id": str(payment.order_id),
                            "payment_key": payment.payment_key,
                            "amount": payment.amount,
                            "status": payment.status,
                            "payment_type": payment.payment_type
                        },
                        "message": "결제가 완료되었습니다"
                    }
                
                logger.error(f"결제 승인 실패: {result}")
                return {
                    "success": False,
                    "message": f"결제 처리 중 오류가 발생했습니다: {result.get('message', '알 수 없는 오류')}"
                }
                
    except Exception as e:
        logger.error(f"결제 확인 중 예외 발생: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=str(e)
        )


@app.get("/api/payments/{payment_key}")
async def get_payment(
    payment_key: str,
    db: Session = Depends(get_db)
):
    try:
        async with aiohttp.ClientSession() as session:
            headers = {
                "Authorization": f"Basic {TOSS_ENCODED_SECRET_KEY}",
                "Content-Type": "application/json"
            }
            
            async with session.get(
                f"https://api.tosspayments.com/v1/payments/{payment_key}",
                headers=headers
            ) as response:
                result = await response.json()
                
                if response.status == 200:
                    return {
                        "success": True,
                        "payment": result
                    }
                    
                return {
                    "success": False,
                    "message": result.get("message", "결제 정보 조회에 실패했습니다")
                }
                
    except Exception as e:
        logger.error(f"결제 조회 중 오류 발생: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=str(e)
        )
    
    # 결제 대기 중인 주문 자동 삭제를 위한 엔드포인트
@app.delete("/api/orders/{order_id}")
async def delete_pending_order(order_id: int, db: Session = Depends(get_db)):
    try:
        # 주문 조회
        order = db.query(models.Order).filter(
            and_(
                models.Order.id == order_id,
                models.Order.payment_status == 0  # 결제 대기 상태인 주문만
            )
        ).first()
        
        if not order:
            raise HTTPException(
                status_code=404, 
                detail="주문을 찾을 수 없거나 이미 결제가 완료된 주문입니다."
            )

        # 같은 시간에 생성된 같은 사용자의 모든 주문 취소 처리
        related_orders = db.query(models.Order).filter(
            and_(
                models.Order.user_id == order.user_id,
                models.Order.order_time == order.order_time,
                models.Order.payment_status == 0
            )
        ).all()

        try:
            current_time = datetime.now(pytz.timezone('Asia/Seoul'))
            update_query = text("""
                UPDATE orders 
                SET status = '취소', 
                    is_completed = 2,
                    completed_time = :completed_time
                WHERE id = :order_id
            """)
            
            for related_order in related_orders:
                db.execute(
                    update_query,
                    {
                        'completed_time': current_time,
                        'order_id': related_order.id
                    }
                )
            db.commit()
            
            return JSONResponse(
                status_code=200,
                content={
                    "success": True,
                    "message": "결제 대기 중인 주문이 취소되었습니다."
                }
            )
            
        except Exception as db_error:
            db.rollback()
            logger.error(f"주문 취소 중 DB 오류: {str(db_error)}")
            raise HTTPException(
                status_code=500,
                detail="주문 취소 중 오류가 발생했습니다."
            )

    except HTTPException as http_error:
        raise http_error
    except Exception as e:
        logger.error(f"주문 취소 중 오류 발생: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

# 결제 대기 주문 자동 정리를 위한 스케줄러 함수
async def cleanup_pending_orders(db: Session):
    try:
        # 현재 시간 기준 30분 이전
        cutoff_time = datetime.now(pytz.timezone('Asia/Seoul')) - timedelta(minutes=30)
        current_time = datetime.now(pytz.timezone('Asia/Seoul'))
        
        # 30분 이상 경과된 결제 대기 주문 조회
        pending_orders = db.query(models.Order).filter(
            and_(
                models.Order.payment_status == 0,
                models.Order.order_time < cutoff_time,
                models.Order.status != '취소',
                models.Order.is_completed != 2
            )
        ).all()

        if pending_orders:
            # 조회된 주문들 취소 처리
            update_query = text("""
                UPDATE orders 
                SET status = '취소', 
                    is_completed = 2,
                    completed_time = :completed_time
                WHERE id IN :order_ids
            """)
            
            order_ids = [order.id for order in pending_orders]
            result = db.execute(
                update_query,
                {
                    'completed_time': current_time,
                    'order_ids': tuple(order_ids)
                }
            )
            
            db.commit()
            logger.info(f"{len(pending_orders)}개의 미결제 주문이 자동 취소되었습니다.")
        
    except Exception as e:
        db.rollback()
        logger.error(f"미결제 주문 자동 취소 중 오류 발생: {str(e)}")

# FastAPI 시작 시 스케줄러 설정
@app.on_event("startup")
async def start_scheduler():
    from apscheduler.schedulers.asyncio import AsyncIOScheduler
    from apscheduler.triggers.interval import IntervalTrigger
    
    scheduler = AsyncIOScheduler()
    
    # 1분마다 미결제 주문 정리
    scheduler.add_job(
        cleanup_pending_orders,
        IntervalTrigger(minutes=15),
        args=[next(get_db())]
    )
    
    scheduler.start()

# ----- uvicorn 실행 부분 -----
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)