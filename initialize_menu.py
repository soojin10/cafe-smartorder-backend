import sys
import os

# 상위 디렉토리를 Python 경로에 추가하여 모듈을 import할 수 있게 함
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database import SessionLocal
from models import Menu
import models
import logging

# 로깅 설정
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def initialize_menu():
    db = SessionLocal()
    try:
        # 기존 메뉴 삭제
        db.query(Menu).delete()
        logger.info("기존 메뉴 삭제 완료")
        
        # 위의 default_menus 데이터를 여기에 복사
        default_menus = [
            {
                "name": "아메리카노", "price": 2500, 
                "category": "COFFEE", "image_url": "https://ifh.cc/g/CwRFo7.jpg", "is_available": True
            },
            {
                "name": "카페라떼", "price": 3500,
                "category": "COFFEE", "image_url": "https://ifh.cc/g/3g9KSV.jpg", "is_available": True
            },
            {
                "name": "카푸치노", "price": 3500,
                "category": "COFFEE", "image_url": "https://ifh.cc/g/9koWNq.jpg", "is_available": True
            },
            {
                "name": "바닐라라떼", "price": 3900,
                "category": "COFFEE", "image_url": "https://ifh.cc/g/R7fpoO.jpg", "is_available": True
            },
            {
                "name": "카페모카", "price": 4300,
                "category": "COFFEE", "image_url": "https://ifh.cc/g/haTG2Q.jpg", "is_available": True
            },
            {
                "name": "민트모카", "price": 4300,
                "category": "COFFEE", "image_url": "https://ifh.cc/g/T4Dfht.jpg", "is_available": True
            },
            {
                "name": "화이트모카", "price": 4300,
                "category": "COFFEE", "image_url": "https://ifh.cc/g/vAaFmA.jpg", "is_available": True
            },
            {
                "name": "사케라또", "price": 2900, 
                "category": "COFFEE", "image_url": "https://ifh.cc/g/0FgohH.jpg", "is_available": True
            },
            {
                "name": "아포카토", "price": 3800, 
                "category": "COFFEE", "image_url": "https://ifh.cc/g/r7xpBr.jpg", "is_available": True
            },
            {
                "name": "디카페인 콜드브루 라떼", "price": 4000, 
                "category": "COFFEE", "image_url": "https://ifh.cc/g/3g9KSV.jpg", "is_available": True
            },
            {
                "name": "디카페인 콜드브루 아메리카노", "price": 3000, 
                "category": "COFFEE", "image_url": "https://ifh.cc/g/CwRFo7.jpg", "is_available": True
            },
            {
                "name": "밀크티", "price": 3500, 
                "category": "LATTE", "image_url": "https://ifh.cc/g/05ZB4X.jpg", "is_available": True
            },
            {
                "name": "초코라떼", "price": 3500, 
                "category": "LATTE", "image_url": "https://ifh.cc/g/xV8V9X.jpg", "is_available": True
            },
            {
                "name": "다크초코라떼", "price": 3800, 
                "category": "LATTE", "image_url": "https://ifh.cc/g/kABDVy.jpg", "is_available": True
            },
            {
                "name": "화이트초코라떼", "price": 3800,
                "category": "LATTE", "image_url": "https://ifh.cc/g/nXYXzh.jpg", "is_available": True
            },
            {
                "name": "민트초코라떼", "price": 3800, 
                "category": "LATTE", "image_url": "https://ifh.cc/g/NHcrxm.jpg", "is_available": True
            },
            {
                "name": "그린티라떼", "price": 3800, 
                "category": "LATTE", "image_url": "https://ifh.cc/g/73xVna.jpg", "is_available": True
            },
            {
                "name": "고구마라떼", "price": 4300, 
                "category": "LATTE", "image_url": "https://ifh.cc/g/WGLyNQ.jpg", "is_available": True
            },
            {
                "name": "카라멜토피넛라떼", "price": 4500, 
                "category": "LATTE", "image_url": "https://ifh.cc/g/YCTPoa.jpg", "is_available": True
            },
            {
                "name": "딸기라떼", "price": 3800,
                "category": "LATTE", "image_url": "https://ifh.cc/g/Hr4ZFY.jpg", "is_available": True
            },
            {
                "name": "루베리라떼", "price": 3800,
                "category": "LATTE", "image_url": "https://ifh.cc/g/rYpKLT.jpg", "is_available": True
            },
            {
                "name": "달고나라떼", "price": 4500,
                "category": "LATTE", "image_url": "https://ifh.cc/g/Ts1hmx.jpg", "is_available": True
            },
            {
                "name": "홍차", "price": 2500, 
                "category": "TEA", "image_url": "https://ifh.cc/g/kKZGpp.jpg", "is_available": True
            },
            {
                "name": "페퍼민트", "price": 2500, 
                "category": "TEA", "image_url": "https://ifh.cc/g/95Vn4W.jpg", "is_available": True
            },
            {
                "name": "캐모마일티", "price": 2500, 
                "category": "TEA", "image_url": "https://ifh.cc/g/86vY9d.jpg", "is_available": True
            },
            {
                "name": "자스민티", "price": 2500, 
                "category": "TEA", "image_url": "https://ifh.cc/g/sx0tOY.jpg", "is_available": True
            },
            {
                "name": "로즈마리티", "price": 2500, 
                "category": "TEA", "image_url": "https://ifh.cc/g/a2pzXf.jpg", "is_available": True
            },
            {
                "name": "유자차", "price": 3500, 
                "category": "TEA", "image_url": "https://ifh.cc/g/pRmr9k.jpg", "is_available": True
            },
            {
                "name": "레몬차", "price": 3500, 
                "category": "TEA", "image_url": "https://ifh.cc/g/xqS2P3.jpg", "is_available": True
            },
            {
                "name": "모과차", "price": 3500,
                "category": "TEA", "image_url": "https://ifh.cc/g/PhQhkx.jpg", "is_available": True
            },
            {
                "name": "플레인 요거트 스무디", "price": 4300, 
                "category": "SMOOTHE", "image_url": "https://ifh.cc/g/0zllgZ.jpg", "is_available": True
            },
            {
                "name": "딸기 요거트 스무디", "price": 4500, 
                "category": "SMOOTHE", "image_url": "https://ifh.cc/g/gqaBmk.jpg", "is_available": True
            },
            {
                "name": "키위 요거트 스무디", "price": 4500, 
                "category": "SMOOTHE", "image_url": "https://ifh.cc/g/o1WwfW.jpg", "is_available": True
            },
            {
                "name": "망고 요거트 스무디", "price": 4500, 
                "category": "SMOOTHE", "image_url": "https://ifh.cc/g/YNFfR6.jpg", "is_available": True
            },
            {
                "name": "블루베리 요거트 스무디", "price": 4500, 
                "category": "SMOOTHE", "image_url": "https://ifh.cc/g/DwFBJX.jpg", "is_available": True
            },
            {
                "name": "딸기 바나나 요거트 스무디", "price": 4800, 
                "category": "SMOOTHE", "image_url": "https://ifh.cc/g/RYAwNb.jpg", "is_available": True
            },
            {
                "name": "망고 바나나 스무디", "price": 4800,
                "category": "SMOOTHE", "image_url": "https://ifh.cc/g/hGzHXw.jpg", "is_available": True
            },
            {
                "name": "홍시 스무디", "price": 4800,
                "category": "SMOOTHE", "image_url": "https://ifh.cc/g/N74YRQ.jpg", "is_available": True
            },
            {
                "name": "바닐라 밀크 쉐이크", "price": 4300,
                "category": "SHAKE/FRAPPE", "image_url": "https://ifh.cc/g/LJ7ApK.jpg", "is_available": True
            },
            {
                "name": "카페 바닐라 밀크쉐이크", "price": 4800,
                "category": "SHAKE/FRAPPE", "image_url": "https://ifh.cc/g/YPs2XP.jpg", "is_available": True
            },
            {
                "name": "그린티 프라페", "price": 4500,
                "category": "SHAKE/FRAPPE", "image_url": "https://ifh.cc/g/ysGFzd.jpg", "is_available": True
            },
            {
                "name": "초코 프라페", "price": 4500, 
                "category": "SHAKE/FRAPPE", "image_url": "https://ifh.cc/g/kJlvhX.jpg", "is_available": True
            },
            {
                "name": "카페모카 프라페", "price": 4800,
                "category": "SHAKE/FRAPPE", "image_url": "https://ifh.cc/g/cA0X25.jpg", "is_available": True
            },
            {
                "name": "쿠키 바닐라 프라페", "price": 4500,
                "category": "SHAKE/FRAPPE", "image_url": "https://ifh.cc/g/JTS356.jpg", "is_available": True
            },
            {
                "name": "복숭아 아이스티", "price": 2900,
                "category": "BEVERAGE", "image_url": "https://ifh.cc/g/pr9DSs.jpg", "is_available": True
            },
            {
                "name": "레몬 에이드", "price": 3800, 
                "category": "BEVERAGE", "image_url": "https://ifh.cc/g/l0h9z8.jpg", "is_available": True
            },
            {
                "name": "청포도 에이드", "price": 3800, 
                "category": "BEVERAGE", "image_url": "https://ifh.cc/g/KXZc5Y.jpg", "is_available": True
            },
            {
                "name": "자몽 에이드", "price": 3800,
                "category": "BEVERAGE", "image_url": "https://ifh.cc/g/Jpnz12.jpg", "is_available": True
            },
            {
                "name": "애플망고 에이드", "price": 3800,
                "category": "BEVERAGE", "image_url": "https://ifh.cc/g/HoChCn.jpg", "is_available": True
            },
            {
                "name": "햄치즈 샌드위치", "price": 2500, 
                "category": "BAKERY/DESSERT", "image_url": "https://ifh.cc/g/JP9q4X.jpg", "is_available": True
            },
            {
                "name": "토마토에그햄치즈", "price": 3800,
                "category": "BAKERY/DESSERT", "image_url": "https://ifh.cc/g/bbP5qz.jpg", "is_available": True
            },
            {
                "name": "크로크무슈", "price": 3500,
                "category": "BAKERY/DESSERT", "image_url": "https://ifh.cc/g/cCvA4S.jpg", "is_available": True
            },
            {
                "name": "초코칩 쿠키", "price": 1500, 
                "category": "BAKERY/DESSERT", "image_url": "https://ifh.cc/g/XTYdZn.jpg", "is_available": True
            },
            {
                "name": "청크초콜릿 쿠키", "price": 1500,
                "category": "BAKERY/DESSERT", "image_url": "https://i.postimg.cc/kG35TqJp/image.jpg", "is_available": True
            },
            {
                "name": "마카다미아 쿠키", "price": 1500,
                "category": "BAKERY/DESSERT", "image_url": "https://i.postimg.cc/wTzvJqbt/image.jpg", "is_available": True
            },
            {
                "name": "반미 치즈치킨 샌드위치", "price": 4500, 
                "category": "BAKERY/DESSERT", "image_url": "https://i.postimg.cc/SNGKfBwg/0-7.jpg", "is_available": True
            },
            {
                "name": "월넛쿠키", "price": 1500,
                "category": "BAKERY/DESSERT", "image_url": "https://ifh.cc/g/AYkfGl.jpg", "is_available": True
            },
            {
                "name": "다크 초코 피칸머핀", "price": 3000,
                "category": "BAKERY/DESSERT", "image_url": "https://ifh.cc/g/6wV4So.jpg", "is_available": True
            },
        ]  

        # 메뉴 추가
        for menu_data in default_menus:
            menu = Menu(
                name=menu_data["name"],
                price=menu_data["price"],
                category=menu_data["category"],
                image_url=menu_data["image_url"],
                is_available=menu_data["is_available"]
            )
            db.add(menu)
            logger.info(f"메뉴 추가: {menu_data['name']}")

        db.commit()
        logger.info("메뉴 초기화 완료")

    except Exception as e:
        db.rollback()
        logger.error(f"메뉴 초기화 중 오류 발생: {str(e)}")
        raise
    finally:
        db.close()

if __name__ == "__main__":
    initialize_menu()