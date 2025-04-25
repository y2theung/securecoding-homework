# securecoding-homework
중고거래 플랫폼
# 옛흥마켓 

Flask + MySQL 기반의 중고거래 웹 플랫폼입니다.  
상품 등록, 쪽지 채팅, 송금 기능, 마이페이지, 차단 기능까지 포함된 경량 웹 서비스입니다.

---

## 주요 기능

-  회원가입, 로그인 (JWT 기반 인증)
-  상품 등록/조회/수정/삭제
-  사용자 간 쪽지 및 실시간 채팅 UI
-  송금 기능 (채팅 내에서 전송)
-  사용자 및 상품 차단 기능
-  마이페이지에서 개인정보 및 거래내역 확인
-  상품 검색

---

##  실행 방법

### 1. 저장소 클론
```bash
git clone https://github.com/yourusername/yetheung-market.git
cd yetheung-market

###2. 가상환경 생성 및 활성화
'''bash
python3 -m venv .venv
source .venv/bin/activate  # (Windows는 .venv\Scripts\activate)

###3. 필요 패키지 설치
```bash
pip install -r requirements.txt

###4. 데이터베이스 초기화
'''bash
flask shell
>>> from app import db
>>> db.create_all()

###5. 서버 실행
```bash
python app.py
# 또는
flask run
