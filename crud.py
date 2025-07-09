from sqlalchemy.orm import Session
import models, schemas
from fastapi import HTTPException
from auth import get_password_hash
from datetime import datetime

# 사용자 조회 (ID로)
def get_user(db: Session, user_id: int):
    return db.query(models.User).filter(models.User.id == user_id).first()

# 이메일로 사용자 조회
def get_user_by_email(db: Session, email: str):
    return db.query(models.User).filter(models.User.email == email).first()

# 모든 사용자 조회 (페이지네이션 가능)
def get_users(db: Session, skip: int = 0, limit: int = 100):
    return db.query(models.User).offset(skip).limit(limit).all()

# 사용자 생성
def create_user(db: Session, user: schemas.UserCreate):
    # get_password_hash 함수를 사용하여 비밀번호 해싱
    hashed_password = get_password_hash(user.password)
    db_user = models.User(
        email=user.email,
        username=user.username,
        hashed_password=hashed_password  # 해싱된 비밀번호 저장
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return schemas.User.from_orm(db_user)

# 사용자 정보 업데이트
def update_user(db: Session, user: models.User, user_update: schemas.User):
    if user_update.username is not None:
        user.username = user_update.username
    if user_update.email is not None:
        user.email = user_update.email
    db.commit()
    db.refresh(user)
    return schemas.User.from_orm(user)  # Pydantic 모델로 반환

# 사용자 삭제
def delete_user(db: Session, user_id: int):
    db_user = db.query(models.User).filter(models.User.id == user_id).first()
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    db.delete(db_user)
    db.commit()
    return schemas.User.from_orm(db_user)  # 삭제된 사용자 정보 반환

# 메뉴 관련 CRUD 함수 추가
def get_menu(db: Session, menu_id: int):
    return db.query(models.Menu).filter(models.Menu.id == menu_id).first()

def get_menus(db: Session, skip: int = 0, limit: int = 100):
    return db.query(models.Menu).offset(skip).limit(limit).all()

def create_menu(db: Session, menu: schemas.MenuItem):
    db_menu = models.Menu(**menu.dict())
    db.add(db_menu)
    db.commit()
    db.refresh(db_menu)
    return db_menu

def update_menu(db: Session, menu_id: int, menu: schemas.MenuItem):
    db_menu = get_menu(db, menu_id)
    if not db_menu:
        raise HTTPException(status_code=404, detail="Menu not found")
    
    for key, value in menu.dict().items():
        setattr(db_menu, key, value)
    
    db.commit()
    db.refresh(db_menu)
    return db_menu

def delete_menu(db: Session, menu_id: int):
    db_menu = get_menu(db, menu_id)
    if not db_menu:
        raise HTTPException(status_code=404, detail="Menu not found")
    
    db.delete(db_menu)
    db.commit()
    return db_menu

def create_payment(db: Session, payment_data: dict):
    try:
        db_payment = models.Payment(
            order_id=payment_data["order_id"],
            payment_key=payment_data["payment_key"],
            amount=payment_data["amount"],
            status=payment_data["status"],
            payment_type=payment_data["payment_type"],
            created_at=datetime.now()
        )
        db.add(db_payment)
        db.commit()
        db.refresh(db_payment)
        return db_payment
    except Exception as e:
        db.rollback()
        logger.error(f"결제 정보 저장 중 오류: {str(e)}")
        raise


def update_payment_status(db: Session, payment_key: str, status: str, payment_data: dict = None):
    payment = db.query(models.Payment).filter(
        models.Payment.payment_key == payment_key
    ).first()
    if payment:
        payment.status = status
        if payment_data:
            for key, value in payment_data.items():
                if hasattr(payment, key):
                    setattr(payment, key, value)
        payment.updated_at = datetime.utcnow()
        db.commit()
        db.refresh(payment)
    return payment

def get_payment_by_order_id(db: Session, order_id: int):
    return db.query(models.Payment).filter(
        models.Payment.order_id == order_id
    ).first()
