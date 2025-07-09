# Cafe SmartOrder Backend

## 프로젝트 개요
카페 스마트오더 애플리케이션의 백엔드 서버입니다.  
사용자 주문, 회원관리, 메뉴 관리, 주문 처리 및 관리자 웹페이지 연동 기능을 FastAPI와 MariaDB를 사용해 구현했습니다.

## 사용 기술
- Python 3.x
- FastAPI
- MariaDB
- Ubuntu 서버 (원격 관리)
- TablePlus (DB 관리)
- Git (버전 관리)

## 주요 기능
- 회원 가입 및 로그인, 인증 처리
- 주문 접수 및 처리 API
- 관리자 웹페이지와의 데이터 연동
- 서버 설정 및 운영 (Ubuntu, PuTTY)
- API 엔드포인트를 통한 앱-서버 통신

## 실행 방법
```bash
# 의존성 설치
pip install -r requirements.txt

# 서버 실행
uvicorn main:app --reload
