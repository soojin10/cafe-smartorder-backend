from passlib.context import CryptContext

# 패스워드 해싱 컨텍스트 생성
pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

# 해시 생성
password = "1234"
hashed_password = pwd_context.hash(password)

print("해시:", hashed_password)

# 해시 검증
is_verified = pwd_context.verify(password, hashed_password)
print("검증 결과:", is_verified)

