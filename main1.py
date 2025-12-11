from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, ForeignKey, Time
from sqlalchemy.orm import sessionmaker, declarative_base, relationship, Session
from passlib.hash import argon2
from datetime import datetime, timedelta, timezone, time
from jose import jwt, JWTError
from typing import Optional, List

# ==========================================================
# CONFIG
# ==========================================================
SECRET_KEY = "SUPER_SECRET_KEY_CHANGE_ME"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
DATABASE_URL = "postgresql+asyncpg://postgres:songya15/02@localhost:5432/clinique"

engine = create_engine(DATABASE_URL, echo=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# ==========================================================
# MODELES SQL
# ==========================================================
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
    appointments = relationship("RendezVous", back_populates="docteur", cascade="all, delete-orphan")

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
    user = relationship("User")
    docteur = relationship("Docteur")

Base.metadata.create_all(bind=engine)

# ==========================================================
# SCHEMAS
# ==========================================================
class UserCreate(BaseModel):
    fullname: str
    email: str
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

class UserUpdate(BaseModel):
    fullname: Optional[str] = None
    address: Optional[str] = None
    password: Optional[str] = None

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
    id: int
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

# ==========================================================
# UTILS
# ==========================================================
def hash_password(password: str):
    return argon2.hash(password)

def verify_password(plain_password, hashed):
    return argon2.verify(plain_password, hashed)

def create_access_token(data: dict):
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = data.copy()
    payload.update({"exp": int(expire.timestamp())})
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def normalize_time_string(t: str) -> time:
    if t is None:
        return None
    t = t.strip()
    formats = ["%I:%M %p", "%I:%M%p", "%H:%M:%S", "%H:%M"]
    for fmt in formats:
        try:
            dt = datetime.strptime(t, fmt)
            return dt.time()
        except ValueError:
            continue
    try:
        dt = datetime.strptime(t.upper(), "%I:%M %p")
        return dt.time()
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Format d'heure invalide: {t}")

def serialize_rdv(rdv: RendezVous) -> dict:
    return {
        "id": rdv.id_rdv,
        "user_id": rdv.user_id,
        "id_doc": rdv.id_doc,
        "fullname": rdv.fullname,
        "email": rdv.email,
        "fullname_doc": rdv.fullname_doc,
        "mail_doc": rdv.mail_doc,
        "date_rdv": rdv.date_rdv,
        "heure_rdv": rdv.heure_rdv.strftime("%H:%M:%S") if rdv.heure_rdv else None,
        "hopital": rdv.hopital,
    }

# ==========================================================
# SESSION
# ==========================================================
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        if not email:
            raise HTTPException(status_code=401, detail="Token invalide")
    except JWTError:
        raise HTTPException(status_code=401, detail="Token invalide")
    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=401, detail="Utilisateur introuvable")
    return user

# ==========================================================
# APP
# ==========================================================
app = FastAPI(title="API Suivi Santé")

# ======================= UTILISATEURS =====================
@app.post("/register", response_model=UserOut)
def register(user: UserCreate, db: Session = Depends(get_db)):
    existing = db.query(User).filter(User.email == user.email).first()
    if existing:
        raise HTTPException(status_code=400, detail="Email déjà utilisé")
    hashed = hash_password(user.password)
    new_user = User(
        fullname=user.fullname,
        email=user.email,
        address=user.address,
        password=hashed
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

@app.post("/login", response_model=Token)
def login(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == form.username).first()
    if not user or not verify_password(form.password, user.password):
        raise HTTPException(status_code=401, detail="Identifiants incorrects")
    token = create_access_token({"sub": user.email})
    return {"access_token": token, "token_type": "bearer"}

@app.get("/me", response_model=UserOut)
def get_profile(current_user: User = Depends(get_current_user)):
    return current_user

# ======================= DONNEES PATIENT =====================
@app.post("/patient_data", response_model=PatientDataOut)
def add_data(data: PatientDataCreate, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    entry = PatientData(
        user_id=current_user.user_id,
        tension=data.tension,
        poids=data.poids,
        temperature=data.temperature,
        frequence_cardiaque=data.frequence_cardiaque,
        symptome=data.symptome
    )
    db.add(entry)
    db.commit()
    db.refresh(entry)
    return entry

@app.get("/patient_data", response_model=List[PatientDataOut])
def list_data(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return db.query(PatientData).filter(PatientData.user_id == current_user.user_id).all()

# ======================= RENDEZ-VOUS =====================
@app.post("/rendez_vous", response_model=RendezVousOut)
def add_rendez_vous(data: RendezVousCreate, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    doctor = db.query(Docteur).filter(Docteur.id_doc == data.id_doc).first()
    if not doctor:
        raise HTTPException(status_code=404, detail="Médecin introuvable")
    heure_mysql = normalize_time_string(data.heure_rdv)
    rdv = RendezVous(
        user_id=current_user.user_id,
        id_doc=doctor.id_doc,
        fullname=current_user.fullname,
        email=current_user.email,
        fullname_doc=doctor.fullname_doc,
        mail_doc=doctor.mail_doc,
        date_rdv=data.date_rdv,
        heure_rdv=heure_mysql,
        hopital=data.hopital
    )
    db.add(rdv)
    db.commit()
    db.refresh(rdv)
    return serialize_rdv(rdv)

@app.get("/rendez_vous", response_model=List[RendezVousOut])
def get_rendez_vous(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    rdvs = db.query(RendezVous).filter(RendezVous.user_id == current_user.user_id).all()
    return [serialize_rdv(r) for r in rdvs]

@app.delete("/rendez_vous/{rdv_id}")
def delete_rendez_vous(rdv_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    rdv = db.query(RendezVous).filter(RendezVous.id_rdv == rdv_id).first()
    if not rdv:
        raise HTTPException(status_code=404, detail="Rendez-vous non trouvé")
    if rdv.user_id != current_user.user_id:
        raise HTTPException(status_code=403, detail="Non autorisé")
    db.delete(rdv)
    db.commit()
    return {"message": "Rendez-vous supprimé avec succès"}

@app.put("/rendez_vous/{rdv_id}", response_model=RendezVousOut)
def update_rendez_vous(rdv_id: int, data: RendezVousCreate, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    rdv = db.query(RendezVous).filter(rdv_id == rdv_id).first()
    if not rdv:
        raise HTTPException(status_code=404, detail="Rendez-vous non trouvé")
    if rdv.user_id != current_user.user_id:
        raise HTTPException(status_code=403, detail="Non autorisé")
    doctor = db.query(Docteur).filter(Docteur.id_doc == data.id_doc).first()
    if not doctor:
        raise HTTPException(status_code=404, detail="Médecin introuvable")
    heure_mysql = normalize_time_string(data.heure_rdv)
    rdv.id_doc = data.id_doc
    rdv.fullname_doc = doctor.fullname_doc
    rdv.mail_doc = doctor.mail_doc
    rdv.date_rdv = data.date_rdv
    rdv.heure_rdv = heure_mysql
    rdv.hopital = data.hopital
    db.commit()
    db.refresh(rdv)
    return serialize_rdv(rdv)

# ======================= MISE À JOUR PROFIL =====================
@app.put("/me/update", response_model=UserOut)
def update_profile(update: UserUpdate, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.user_id == current_user.user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Utilisateur introuvable")
    if update.fullname:
        user.fullname = update.fullname
    if update.address:
        user.address = update.address
    if update.password:
        user.password = hash_password(update.password)
    db.commit()
    db.refresh(user)
    return user

# ======================= DOCTEURS =====================
@app.get("/docteurs", response_model=List[DocteurOut])
def list_docteurs(db: Session = Depends(get_db)):
    return db.query(Docteur).all()

# ======================= CHANGEMENT DE MOT DE PASSE =====================
@app.put("/me/change-password")
def change_password(
    current_password: str,
    new_password: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if not verify_password(current_password, current_user.password):
        raise HTTPException(status_code=400, detail="Mot de passe actuel incorrect")
    current_user.password = hash_password(new_password)
    db.commit()
    return {"message": "Mot de passe mis à jour avec succès"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=10000)