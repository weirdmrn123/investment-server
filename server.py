from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import Column, Integer, Numeric, String, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
import uvicorn
from dotenv import load_dotenv
import os
import random
from typing import List
import bcrypt 
import resend
import redis
from pydantic import BaseModel
from typing import Optional
from cachetools import TTLCache
from fastapi import Header

# Load environment variables
load_dotenv()

app = FastAPI()

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Change this in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Database Setup
DATABASE_URL = os.getenv("DATABASE_URL")
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


# Define User Model
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    full_name = Column(String, nullable=False)  # Full Name
    email = Column(String, unique=True, index=True, nullable=False)
    gender = Column(String, nullable=False)  # Male/Female
    country = Column(String, nullable=False)
    address = Column(String, nullable=False)
    mobile = Column(String, unique=True, nullable=False)
    employment_status = Column(String, nullable=False)  # Employed, Unemployed, etc.
    industry = Column(String, nullable=True)  # Optional
    salary_range = Column(String, nullable=False)  # Optional
    password = Column(String, nullable=False)
    
    withdrawable_balance = Column(Numeric(10, 2), default=50)
    capital_invested = Column(Numeric(10, 2), default=0)
    profit = Column(Numeric(10, 2), default=0)
    investment_plan = Column(String, nullable=False, default="No active plan")  # Default plan
    account_status = Column(String, nullable=False, default="Active")  # Default status
    kyc = Column(String, nullable=False, default="Not Verified")  # Default status

class NewProjectUser(Base):
    __tablename__ = "wealth"
    id = Column(Integer, primary_key=True, index=True)
    full_name = Column(String, nullable=False)  # Full Name
    email = Column(String, unique=True, index=True, nullable=False)
    gender = Column(String, nullable=False)  # Male/Female
    country = Column(String, nullable=False)
    address = Column(String, nullable=False)
    mobile = Column(String, unique=True, nullable=False)
    employment_status = Column(String, nullable=False)  # Employed, Unemployed, etc.
    industry = Column(String, nullable=True)  # Optional
    salary_range = Column(String, nullable=False)  # Optional
    password = Column(String, nullable=False)
    
    withdrawable_balance = Column(Numeric(10, 2), default=100)
    capital_invested = Column(Numeric(10, 2), default=0)
    profit = Column(Numeric(10, 2), default=0)
    investment_plan = Column(String, nullable=False, default="No active plan")  # Default plan
    account_status = Column(String, nullable=False, default="Active")  # Default status
    kyc = Column(String, nullable=False, default="Not Verified")  # Default status


# Create database tables
Base.metadata.create_all(bind=engine)

# Dependency to get DB session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Initialize Redis for OTP storage
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
redis_client = redis.StrictRedis.from_url(REDIS_URL, decode_responses=True)

resend.api_key = os.getenv("RESEND_API_KEY") # Correct way

@app.get("/")
def read_root():
    return {"message": "Hello, World!"}

@app.get("/health")
def health_check():
    return {"status": "ok"}

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')


# Verify password
def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))

class UserRequest(BaseModel):
    full_name: str
    email: str
    gender: str
    country: str
    address: str
    mobile: str
    employment_status: str
    industry: str
    salary_range: str
    password: str


@app.post("/register")
def register(
    request: UserRequest, 
    db: Session = Depends(get_db) 
    ): 
    # Check if user already exists
    existing_user = db.query(User).filter(User.email == request.email).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    existing_mobile_user = db.query(User).filter(User.mobile == request.mobile).first()
    if existing_mobile_user:
        raise HTTPException(status_code=400, detail="Mobile number already registered")
    
    hashed_password = hash_password(request.password)

    # Create new user
    new_user = User(
        full_name=request.full_name,
        email=request.email,
        gender=request.gender,
        country=request.country,
        address=request.address,
        mobile=request.mobile,
        employment_status=request.employment_status,
        industry=request.industry,
        salary_range=request.salary_range,
        password=hashed_password,  # Consider hashing the password
    )

    # Save user to the database
    db.add(new_user)
    db.commit()
    return {"message": "Registration successful"}

@app.post("/wealth/register")
def register(
    request: UserRequest, 
    db: Session = Depends(get_db) 
    ): 
    # Check if user already exists
    existing_user = db.query(NewProjectUser).filter(NewProjectUser.email == request.email).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    existing_mobile_user = db.query(NewProjectUser).filter(NewProjectUser.mobile == request.mobile).first()
    if existing_mobile_user:
        raise HTTPException(status_code=400, detail="Mobile number already registered")
    
    hashed_password = hash_password(request.password)

    # Create new user
    new_user = NewProjectUser(
        full_name=request.full_name,
        email=request.email,
        gender=request.gender,
        country=request.country,
        address=request.address,
        mobile=request.mobile,
        employment_status=request.employment_status,
        industry=request.industry,
        salary_range=request.salary_range,
        password=hashed_password,  # Consider hashing the password
    )

    # Save user to the database
    db.add(new_user)
    db.commit()
    return {"message": "Registration successful"}

class LoginRequest(BaseModel):
    email: str
    password: str


@app.post("/login")
def login(request: LoginRequest, 
          db: Session = Depends(get_db)
          ):
    user = db.query(User).filter(User.email == request.email).first()

    if user and verify_password(request.password, user.password):  # Use password verification
        return {
        "id": user.id,
        "full_name": user.full_name,
        "email": user.email,
        "gender": user.gender,
        "country": user.country,
        "mobile": user.mobile,
        "address": user.address,
        "withdrawable_balance": user.withdrawable_balance,
        "capital_invested": user.capital_invested,
        "profit": user.profit,
        "investment_plan": user.investment_plan,
        "account_status": user.account_status,
        "kyc": user.kyc
    }
    
    raise HTTPException(status_code=401, detail="Invalid email or password")

@app.post("/wealth/login")
def login(request: LoginRequest, 
          db: Session = Depends(get_db)
          ):
    user = db.query(NewProjectUser).filter(NewProjectUser.email == request.email).first()

    if user and verify_password(request.password, user.password):  # Use password verification
        return {
        "id": user.id,
        "full_name": user.full_name,
        "email": user.email,
        "gender": user.gender,
        "country": user.country,
        "mobile": user.mobile,
        "address": user.address,
        "withdrawable_balance": user.withdrawable_balance,
        "capital_invested": user.capital_invested,
        "profit": user.profit,
        "investment_plan": user.investment_plan,
        "account_status": user.account_status,
        "kyc": user.kyc
    }
    
    raise HTTPException(status_code=401, detail="Invalid email or password")


class EmailRequest(BaseModel):
    email: str

@app.post("/send-otp")
def send_otp(request: EmailRequest):
    email = request.email 
    otp = random.randint(100000, 999999)
    # otp_cache[email] = otp # Store OTP in the in-memory cache
    redis_client.setex(email, 300, otp) 
    try:
        resend.Emails.send({
            "from": "onboarding@resend.dev",
            "to": [email],
            "subject": "Hello World",
            "html": f"Your OTP code is <strong>{otp}</strong>. It is valid for 5 minutes."
        })
        return {"message": "OTP sent successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

class OTPVerification(BaseModel):
    email: str
    otp: int

@app.post("/verify-otp")
def verify_otp(request: OTPVerification, db: Session = Depends(get_db)):
    email = request.email
    otp = request.otp
    # stored_otp = otp_cache.get(email)
    stored_otp = redis_client.get(email)
    if stored_otp and int(stored_otp) == otp:
        redis_client.delete(email)  # Remove OTP from cache after successful verification
        user = db.query(User).filter(User.email == email).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        return {
        "id": user.id,
        "full_name": user.full_name,
        "email": user.email,
        "gender": user.gender,
        "country": user.country,
        "mobile": user.mobile,
        "address": user.address,
        "withdrawable_balance": user.withdrawable_balance,
        "capital_invested": user.capital_invested,
        "profit": user.profit,
        "investment_plan": user.investment_plan,
        "account_status": user.account_status,
        "kyc": user.kyc
    }

    else:
        raise HTTPException(status_code=400, detail="Invalid or expired OTP")
    
class NewProjectUserResponse(BaseModel):
    id: int
    full_name: str
    email: str
    gender: str
    country: str
    address: str
    mobile: str
    employment_status: str
    industry: str
    salary_range: str
    withdrawable_balance: float
    capital_invested: float
    profit: float
    investment_plan: str
    account_status: str
    kyc: str

    class Config:
        from_attributes = True  # Needed for SQLAlchemy model conversion

@app.get("/wealth/allusers", response_model=List[NewProjectUserResponse])
def get_all_users(db: Session = Depends(get_db)):
    users = db.query(NewProjectUser).all()
    return users  # FastAPI will automatically serialize the response

    
@app.get("/users/{email}")
def get_user_by_email(
    email: str, 
    db: Session = Depends(get_db)
    ):
    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    return {
        "id": user.id,
        "full_name": user.full_name,
        "email": user.email,
        "withdrawable_balance": user.withdrawable_balance,
        "capital_invested": user.capital_invested,
        "profit": user.profit,
        "investment_plan": user.investment_plan,
        "account_status": user.account_status,
        "kyc": user.kyc
    }

class UserUpdateRequest(BaseModel):
    full_name: Optional[str] = None
    gender: Optional[str] = None
    country: Optional[str] = None
    address: Optional[str] = None
    mobile: Optional[str] = None
    employment_status: Optional[str] = None
    industry: Optional[str] = None
    salary_range: Optional[str] = None
    password: Optional[str] = None
    
    withdrawable_balance: Optional[int] = None
    capital_invested: Optional[int] = None
    profit: Optional[int] = None
    investment_plan: Optional[str] = None
    account_status: Optional[str] = None
    kyc: Optional[str] = None

@app.put("/edit/{email}")
def update_user(
    email: str, 
    request: UserUpdateRequest, 
    db: Session = Depends(get_db)
    ):
    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Update fields if provided
    update_data = request.dict(exclude_unset=True)

    # If updating password, hash it before saving
    if "password" in update_data:
        update_data["password"] = hash_password(update_data["password"])

    for key, value in update_data.items():
        setattr(user, key, value)

    db.commit()
    db.refresh(user)
    
    return {"message": "User updated successfully", "user": update_data}

@app.delete("/users/{email}")
def delete_user(email: str, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    db.delete(user)
    db.commit()
    
    return {"message": "User deleted successfully"}



if __name__ == "__main__":
    uvicorn.run("server:app", host="0.0.0.0", port=int(os.getenv("PORT", 8000)))
