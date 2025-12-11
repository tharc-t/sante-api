import os
from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from sqlalchemy import Column, Integer, String, Float, DateTime, ForeignKey, Time, text
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import declarative_base, relationship, sessionmaker
from passlib.hash import argon2
from datetime import datetime, timedelta, timezone, time
from jose import jwt, JWTError
from typing import Optional, List

# ------------------ CONFIG ------------------
SECRET_KEY = os.getenv("SECRET_KEY", "SUPER_SECRET_KEY_CHANGE_ME")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
DATABASE_URL = ("postgresql+asyncpg://postgres:songya15/02@localhost:5432/clinique")

engine = create_async_engine(DATABASE_URL, echo=True, future=True)
async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

Base = declarative_base()

# ------------------ MODÈLES ------------------
class User(Base):
    __tablename__ = "users_new"
    user_id = Column(Integer, primary_key=True, autoincrement=True)
    fullname = Column(String(255), nullable=False)
    email = Column(String(255), nullable=False, unique=True)
    address = Column(String(255), nullable=False)
    password = Column(String(255), nullable=False)
    patient_data = relationship("PatientData", back_populates="user", cascade="all, delete-orphan")

class PatientData(Base):
    __tablename__ = "patient_data"
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users_new.user_id", ondelete="CASCADE"))
    tension = Column(Float)
    poids = Column(Float)
    temperature = Column(Float)
    frequence_cardiaque = Column(Float)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    symptome = Column(String(255))
    user = relationship("User", back_populates="patient_data")

class Docteur(Base):
    __tablename__ = "docteur"
    id_doc = Column(Integer, primary_key=True, autoincrement=True)
    fullname_doc = Column(String(255), nullable=False)
    mail_doc = Column(String(255), nullable=False, unique=True)
    specialty = Column(String(255), nullable=False)

class RendezVous(Base):
    __tablename__ = "rendez_vous"
    id_rdv = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users_new.user_id", ondelete="CASCADE"))
    id_doc = Column(Integer, ForeignKey("docteur.id_doc", ondelete="CASCADE"))
    fullname = Column(String(255))
    email = Column(String(255))
    fullname_doc = Column(String(255))
    mail_doc = Column(String(255))
    date_rdv = Column(DateTime)
    heure_rdv = Column(Time)
    hopital = Column(String(255))

# ------------------ SCHÉMAS ------------------
class UserCreate(BaseModel):
    fullname: str
    email: EmailStr
    address: str
    password: str

class UserOut(BaseModel):
    user_id: int
    fullname: str
    email: str
    address: str
    class Config:
        orm_mode = True

class Token(BaseModel):
    access_token: str
    token_type: str

class PatientDataCreate(BaseModel):
    tension: float
    poids: float
    temperature: float
    frequence_cardiaque: float
    symptome: Optional[str] = None

class PatientDataOut(PatientDataCreate):
    id: int
    user_id: int
    created_at: datetime
    class Config:
        orm_mode = True

class RendezVousCreate(BaseModel):
    id_doc: int
    date_rdv: datetime
    heure_rdv: str
    hopital: str

class RendezVousOut(BaseModel):
    id_rdv: int
    user_id: int
    id_doc: int
    fullname: str
    email: str
    fullname_doc: str
    mail_doc: str
    date_rdv: datetime
    heure_rdv: str
    hopital: str
    class Config:
        orm_mode = True

class DocteurOut(BaseModel):
    id_doc: int
    fullname_doc: str
    mail_doc: str
    specialty: str
    class Config:
        orm_mode = True

# ------------------ UTILS ------------------
def hash_password(password: str):
    return argon2.hash(password)

def verify_password(plain_password, hashed):
    return argon2.verify(plain_password, hashed)

def create_access_token(data: dict):
    expire = datetime.now(timezone.utc) + timedelta(minutes=60)
    payload = data.copy()
    payload.update({"exp": int(expire.timestamp())})
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

# ------------------ SESSION ------------------
async def get_db() -> AsyncSession:
    async with async_session() as session:
        yield session

async def get_current_user(token: str = Depends(oauth2_scheme), db: AsyncSession = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        if not email:
            raise HTTPException(status_code=401, detail="Token invalide")
    except JWTError:
        raise HTTPException(status_code=401, detail="Token invalide")
    result = await db.execute(select(User).where(User.email == email))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=401, detail="Utilisateur introuvable")
    return user

# ------------------ APP ------------------
app = FastAPI(title="API Suivi Santé")

# ---------- INSCRIPTION ----------
@app.post("/register", response_model=UserOut)
async def register(user: UserCreate, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.email == user.email))
    if result.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Email déjà utilisé")
    hashed = hash_password(user.password)
    new_user = User(
        fullname=user.fullname,
        email=user.email,
        address=user.address,
        password=hashed
    )
    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)
    return new_user

# ---------- LOGIN ----------
@app.post("/login", response_model=Token)
async def login(form: OAuth2PasswordRequestForm = Depends(), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.email == form.username))
    user = result.scalar_one_or_none()
    if not user or not verify_password(form.password, user.password):
        raise HTTPException(status_code=401, detail="Identifiants incorrects")
    token = create_access_token({"sub": user.email})
    return {"access_token": token, "token_type": "bearer"}

# ---------- PROFIL ----------
@app.get("/me", response_model=UserOut)
async def get_profile(current_user: User = Depends(get_current_user)):
    return current_user

# ---------- DONNEES PATIENT ----------
@app.post("/patient_data", response_model=PatientDataOut)
async def add_data(data: PatientDataCreate, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    entry = PatientData(
        user_id=current_user.user_id,
        tension=data.tension,
        poids=data.poids,
        temperature=data.temperature,
        frequence_cardiaque=data.frequence_cardiaque,
        symptome=data.symptome
    )
    db.add(entry)
    await db.commit()
    await db.refresh(entry)
    return entry

@app.get("/patient_data", response_model=List[PatientDataOut])
async def list_data(current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(PatientData).where(PatientData.user_id == current_user.user_id))
    return result.scalars().all()

# ---------- DOCTEURS ----------
@app.get("/docteurs", response_model=List[DocteurOut])
async def list_docteurs(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Docteur))
    return result.scalars().all()

# ---------- RENDEZ-VOUS ----------
@app.post("/rendez_vous", response_model=RendezVousOut)
async def add_rendez_vous(data: RendezVousCreate, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    doc_result = await db.execute(select(Docteur).where(Docteur.id_doc == data.id_doc))
    doctor = doc_result.scalar_one_or_none()
    if not doctor:
        raise HTTPException(status_code=404, detail="Médecin introuvable")
    from datetime import datetime
    rdv = RendezVous(
        user_id=current_user.user_id,
        id_doc=doctor.id_doc,
        fullname=current_user.fullname,
        email=current_user.email,
        fullname_doc=doctor.fullname_doc,
        mail_doc=doctor.mail_doc,
        date_rdv=data.date_rdv,
        heure_rdv=datetime.strptime(data.heure_rdv, "%H:%M").time(),
        hopital=data.hopital
    )
    db.add(rdv)
    await db.commit()
    await db.refresh(rdv)
    return rdv

@app.get("/rendez_vous", response_model=List[RendezVousOut])
async def get_rendez_vous(current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(RendezVous).where(RendezVous.user_id == current_user.user_id))
    return result.scalars().all()

# ---------- HEALTH ----------
@app.get("/health")
async def health(db: AsyncSession = Depends(get_db)):
    await db.execute(text("SELECT 1"))
    return {"status": "up"}

# ---------- LANCEMENT ----------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=10000)