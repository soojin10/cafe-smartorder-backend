from pydantic import BaseModel, EmailStr, Field
from typing import Optional, List
from datetime import datetime

class UserBase(BaseModel):
    email: EmailStr
    username: str
    password: str
    is_admin: bool = False

class UserCreate(UserBase):
    confirm_password: str = Field(...)
    is_admin: bool = False

class User(UserBase):
    id: int
    is_verified: bool = False
    verification_code: Optional[str] = None

    class Config:
        from_attributes = True

class UserResponse(BaseModel):
    success: bool
    data: dict = {
        "id": int,
        "email": str,
        "username": str,
        "is_admin": bool
    }

class OrderItem(BaseModel):
    id: int
    total_price: int
    status: str
    created_at: datetime

class UserInfoResponse(BaseModel):
    success: bool
    data: dict = {
        "user": {
            "id": int,
            "email": str,
            "username": str
        },
        "orders": List[OrderItem]
    }

    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str
    is_admin: bool

class UserAuthenticate(BaseModel):
    email: EmailStr
    password: str

class EmailRequest(BaseModel):
    email: str

class VerificationResponse(BaseModel):
    success: bool
    message: str
    verificationCode: Optional[str] = None

class VerificationRequest(BaseModel):
    email: str
    verification_code: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

    class Config:
        from_attributes = True

class MenuItem(BaseModel):
    name: Optional[str] = None
    price: Optional[int] = None
    quantity: Optional[int] = None
    category: Optional[str] = None
    image_url: Optional[str] = None
    is_available: Optional[bool] = None

    class Config:
        from_attributes = True

class AutoLoginToken(BaseModel):
    email: str
    auto_login_token: str

class UserUpdate(BaseModel):
    email: str | None = None
    username: str | None = None

    class Config:
        from_attributes = True

class PasswordChange(BaseModel):
    current_password: str
    new_password: str
    confirm_password: str

class PaymentCreate(BaseModel):
    order_id: int
    amount: int

class PaymentResponse(BaseModel):
    payment_key: str
    status: str
    success: bool
    message: str

class PaymentRequest(BaseModel):
    amount: int
    order_name: str
    your_customer_id: str

class PaymentResponse(BaseModel):
    status: str
    message: str
    payment_key: Optional[str] = None
    order_id: Optional[str] = None
    checkout_url: Optional[str] = None

class PaymentConfirmRequest(BaseModel):
    paymentKey: str
    orderId: str
    amount: int

class PaymentStatusResponse(BaseModel):
    success: bool
    status: str
    message: str
    data: Optional[dict] = None