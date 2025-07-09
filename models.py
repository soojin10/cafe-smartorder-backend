from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, JSON, Text, Float
from sqlalchemy.orm import relationship
from database import Base
from datetime import datetime
import pytz

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True)
    username = Column(String(255))
    hashed_password = Column(String(255))
    is_active = Column(Boolean, default=True)
    is_admin = Column(Boolean, default=False)
    verification_code = Column(String(6), nullable=True)
    is_verified = Column(Boolean, default=False)
    auto_login_token = Column(String(64), unique=True, nullable=True)
    orders = relationship("Order", back_populates="user")

class Menu(Base):
    __tablename__ = "menus"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    price = Column(Integer, nullable=False)
    category = Column(String(100), nullable=False)
    image_url = Column(String(500))
    is_available = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class Order(Base):
    __tablename__ = "orders"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    user_name = Column(String(255), nullable=False)
    user_email = Column(String(255), nullable=False)
    menu_id = Column(Integer, ForeignKey('menus.id'))
    unit_price = Column(Integer, nullable=False, default=0)
    total_price = Column(Integer, nullable=False)
    status = Column(String(50), default="준비중")
    order_time = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(pytz.timezone('Asia/Seoul')))
    payment_status = Column(Integer, nullable=True, default=0)
    is_completed = Column(Boolean, default=0)
    completed_time = Column(DateTime(timezone=True), nullable=True)
    is_settled = Column(Boolean, default=False)
    closure = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    quantity = Column(Integer, default=1)
    hot_ice_option = Column(String(10), nullable=True)
    size = Column(String(10), nullable=True)
    shot_quantity = Column(Integer, default=0)
    hazelnut_quantity = Column(Integer, default=0)
    tapioca_quantity = Column(Integer, default=0)
    decaf_quantity = Column(Integer, default=0)
    vanilla_quantity = Column(Integer, default=0)
    whipping_quantity = Column(Integer, default=0)
    icecream_quantity = Column(Integer, default=0)
    
    user = relationship("User", back_populates="orders")
    menu = relationship("Menu")

class Product(Base):
    __tablename__ = "products"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    price = Column(Integer, nullable=False)
    category = Column(String(100), nullable=False)
    image_url = Column(String(500))
    is_available = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class Cart(Base):
    __tablename__ = "carts"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    menu_id = Column(Integer, ForeignKey('menus.id'))
    quantity = Column(Integer, default=1)
    hot_ice_option = Column(String(10), nullable=True)
    size = Column(String(10), nullable=True)
    shot_quantity = Column(Integer, default=0)
    hazelnut_quantity = Column(Integer, default=0)
    tapioca_quantity = Column(Integer, default=0)
    decaf_quantity = Column(Integer, default=0)
    vanilla_quantity = Column(Integer, default=0)
    whipping_quantity = Column(Integer, default=0)
    icecream_quantity = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    user = relationship("User", backref="cart_items")
    menu = relationship("Menu")

class Favorite(Base):
    __tablename__ = "favorites"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    menu_id = Column(Integer, ForeignKey('menus.id'))
    menu_name = Column(String(255), nullable=False)
    price = Column(Integer, nullable=False)
    image_url = Column(String(500))
    total_price = Column(Integer, nullable=False)
    
    hot_ice_option = Column(String(10), nullable=True)
    size = Column(String(10), nullable=True)
    shot_quantity = Column(Integer, default=0)
    hazelnut_quantity = Column(Integer, default=0)
    tapioca_quantity = Column(Integer, default=0)
    decaf_quantity = Column(Integer, default=0)
    vanilla_quantity = Column(Integer, default=0)
    whipping_quantity = Column(Integer, default=0)
    icecream_quantity = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    user = relationship("User", backref="favorites")
    menu = relationship("Menu")

class Poster(Base):
    __tablename__ = "posters"

    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String(255), nullable=False)
    image_url = Column(String(500), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

class Payment(Base):
    __tablename__ = "payments"
    
    id = Column(Integer, primary_key=True, index=True)
    order_id = Column(String)
    payment_key = Column(String(200))
    amount = Column(Integer)
    status = Column(String(50))
    payment_type = Column(String(50))
    created_at = Column(DateTime, default=datetime.utcnow)
