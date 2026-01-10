from fastapi import FastAPI, APIRouter, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, ConfigDict, EmailStr
from typing import List, Optional
import uuid
from datetime import datetime, timezone, timedelta
import jwt
import bcrypt
import random
import asyncio
import socketio
from openai import OpenAI

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ.get('DB_NAME', 'bilgoo')]

# JWT Settings
JWT_SECRET = os.environ.get('JWT_SECRET', 'bilgoo-secret-key-2025')
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = 24 * 7  # 1 week

# Admin emails - only these users can manage questions
ADMIN_EMAILS = os.environ.get('ADMIN_EMAILS', 'admin@bilgoo.com').split(',')

# Emergent LLM Key for AI question generation
EMERGENT_LLM_KEY = os.environ.get('EMERGENT_LLM_KEY', 'sk-emergent-bEfC488A14816C3423')

# Create FastAPI app
fastapi_app = FastAPI(title="Bilgoo API")

# Create Socket.IO server
sio = socketio.AsyncServer(
    async_mode='asgi',
    cors_allowed_origins='*',
    logger=False,
    engineio_logger=False
)

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")

# Security
security = HTTPBearer()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Avatar colors
AVATAR_COLORS = [
    '#6C63FF', '#FF6B6B', '#4CAF50', '#FF9800', '#9C27B0',
    '#00BCD4', '#E91E63', '#3F51B5', '#009688', '#FFC107'
]

# Categories
CATEGORIES = [
    {"id": "genel", "name": "Genel Kültür", "icon": "book"},
    {"id": "tarih", "name": "Tarih", "icon": "time"},
    {"id": "cografya", "name": "Coğrafya", "icon": "globe"},
    {"id": "bilim", "name": "Bilim & Teknoloji", "icon": "flask"},
    {"id": "spor", "name": "Spor", "icon": "football"},
    {"id": "sanat", "name": "Sanat & Edebiyat", "icon": "brush"},
    {"id": "muzik", "name": "Müzik & Sinema", "icon": "musical-notes"},
]

# =========================
# Pydantic Models
# =========================

class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=30)
    email: EmailStr
    password: str = Field(..., min_length=6)

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class UserResponse(BaseModel):
    id: str
    username: str
    email: str
    score: int = 0
    friends: List[str] = []
    avatar_color: str
    is_admin: bool = False
    created_at: str

class AuthResponse(BaseModel):
    access_token: str
    user: UserResponse

class FriendResponse(BaseModel):
    id: str
    username: str
    score: int
    avatar_color: str
    is_online: bool = False

class RoomCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=50)
    question_count: int = Field(..., ge=10, le=20)

class RoomPlayer(BaseModel):
    id: str
    username: str
    avatar_color: str
    score: int = 0
    is_ready: bool = False
    current_answer: Optional[int] = None

class RoomResponse(BaseModel):
    id: str
    name: str
    host_id: str
    host_username: str
    players: List[RoomPlayer]
    question_count: int
    status: str = "waiting"
    current_question_index: int = 0
    created_at: str

class QuestionCreate(BaseModel):
    category: str
    question: str
    options: List[str] = Field(..., min_items=4, max_items=4)
    correct_answer: int = Field(..., ge=0, le=3)

class QuestionResponse(BaseModel):
    id: str
    category: str
    question: str
    options: List[str]
    correct_answer: int
    is_ai_generated: bool = False

class GenerateQuestionsRequest(BaseModel):
    category: str
    count: int = Field(default=5, ge=1, le=20)

# =========================
# Helper Functions
# =========================

def create_token(user_id: str) -> str:
    payload = {
        "sub": user_id,
        "exp": datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRATION_HOURS),
        "iat": datetime.now(timezone.utc)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def verify_token(token: str) -> Optional[str]:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload.get("sub")
    except jwt.PyJWTError:
        return None

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    user_id = verify_token(token)
    if not user_id:
        raise HTTPException(status_code=401, detail="Geçersiz veya süresi dolmuş token")
    
    user = await db.users.find_one({"id": user_id})
    if not user:
        raise HTTPException(status_code=401, detail="Kullanıcı bulunamadı")
    
    # Check if user is admin
    user['is_admin'] = user.get('email', '') in ADMIN_EMAILS
    return user

async def get_admin_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Only allows admin users"""
    user = await get_current_user(credentials)
    if not user.get('is_admin', False):
        raise HTTPException(status_code=403, detail="Bu işlem için admin yetkisi gerekli")
    return user

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed.encode())

# =========================
# Auth Endpoints
# =========================

@api_router.post("/auth/register", response_model=AuthResponse)
async def register(data: UserCreate):
    # Check if email exists
    existing_email = await db.users.find_one({"email": data.email})
    if existing_email:
        raise HTTPException(status_code=400, detail="Bu e-posta zaten kullaniliyor")
    
    # Check if username exists
    existing_username = await db.users.find_one({"username": data.username})
    if existing_username:
        raise HTTPException(status_code=400, detail="Bu kullanici adi zaten kullaniliyor")
    
    user_id = str(uuid.uuid4())
    is_admin = data.email in ADMIN_EMAILS
    user = {
        "id": user_id,
        "username": data.username,
        "email": data.email,
        "password_hash": hash_password(data.password),
        "score": 0,
        "friends": [],
        "avatar_color": random.choice(AVATAR_COLORS),
        "is_admin": is_admin,
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    
    await db.users.insert_one(user)
    
    token = create_token(user_id)
    return AuthResponse(
        access_token=token,
        user=UserResponse(
            id=user["id"],
            username=user["username"],
            email=user["email"],
            score=user["score"],
            friends=user["friends"],
            avatar_color=user["avatar_color"],
            is_admin=user.get("is_admin", False),
            created_at=user["created_at"]
        )
    )

@api_router.post("/auth/login", response_model=AuthResponse)
async def login(data: UserLogin):
    user = await db.users.find_one({"email": data.email})
    if not user or not verify_password(data.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Geçersiz e-posta veya şifre")
    
    is_admin = user.get("email", "") in ADMIN_EMAILS
    token = create_token(user["id"])
    return AuthResponse(
        access_token=token,
        user=UserResponse(
            id=user["id"],
            username=user["username"],
            email=user["email"],
            score=user["score"],
            friends=user.get("friends", []),
            avatar_color=user["avatar_color"],
            is_admin=is_admin,
            created_at=user["created_at"]
        )
    )

@api_router.get("/auth/profile", response_model=UserResponse)
async def get_profile(user: dict = Depends(get_current_user)):
    return UserResponse(
        id=user["id"],
        username=user["username"],
        email=user["email"],
        score=user["score"],
        friends=user.get("friends", []),
        avatar_color=user["avatar_color"],
        is_admin=user.get("is_admin", False),
        created_at=user["created_at"]
    )

# =========================
# Friends Endpoints
# =========================

@api_router.get("/friends", response_model=List[FriendResponse])
async def get_friends(user: dict = Depends(get_current_user)):
    friends = []
    for friend_id in user.get("friends", []):
        friend = await db.users.find_one({"id": friend_id})
        if friend:
            friends.append(FriendResponse(
                id=friend["id"],
                username=friend["username"],
                score=friend["score"],
                avatar_color=friend["avatar_color"],
                is_online=friend_id in online_users
            ))
    return friends

@api_router.get("/users/search", response_model=List[UserResponse])
async def search_users(q: str, user: dict = Depends(get_current_user)):
    if len(q) < 2:
        return []
    
    # Search by username (case-insensitive)
    users = await db.users.find({
        "username": {"$regex": q, "$options": "i"},
        "id": {"$ne": user["id"]}  # Exclude current user
    }).to_list(20)
    
    # Filter out existing friends
    friend_ids = set(user.get("friends", []))
    results = []
    for u in users:
        if u["id"] not in friend_ids:
            results.append(UserResponse(
                id=u["id"],
                username=u["username"],
                email=u["email"],
                score=u["score"],
                friends=u.get("friends", []),
                avatar_color=u["avatar_color"],
                created_at=u["created_at"]
            ))
    
    return results

@api_router.post("/friends/{friend_id}")
async def add_friend(friend_id: str, user: dict = Depends(get_current_user)):
    if friend_id == user["id"]:
        raise HTTPException(status_code=400, detail="Kendinizi arkadas olarak ekleyemezsiniz")
    
    friend = await db.users.find_one({"id": friend_id})
    if not friend:
        raise HTTPException(status_code=404, detail="Kullanici bulunamadi")
    
    if friend_id in user.get("friends", []):
        raise HTTPException(status_code=400, detail="Bu kullanici zaten arkadasiniz")
    
    # Add friend to both users
    await db.users.update_one(
        {"id": user["id"]},
        {"$addToSet": {"friends": friend_id}}
    )
    await db.users.update_one(
        {"id": friend_id},
        {"$addToSet": {"friends": user["id"]}}
    )
    
    return {"message": "Arkadas eklendi"}

@api_router.delete("/friends/{friend_id}")
async def remove_friend(friend_id: str, user: dict = Depends(get_current_user)):
    # Remove friend from both users
    await db.users.update_one(
        {"id": user["id"]},
        {"$pull": {"friends": friend_id}}
    )
    await db.users.update_one(
        {"id": friend_id},
        {"$pull": {"friends": user["id"]}}
    )
    
    return {"message": "Arkadas silindi"}

# =========================
# Room Endpoints
# =========================

@api_router.get("/rooms", response_model=List[RoomResponse])
async def get_rooms(user: dict = Depends(get_current_user)):
    rooms = await db.rooms.find({"status": "waiting"}).to_list(50)
    return [RoomResponse(**room) for room in rooms]

@api_router.post("/rooms", response_model=RoomResponse)
async def create_room(data: RoomCreate, user: dict = Depends(get_current_user)):
    room_id = str(uuid.uuid4())
    room = {
        "id": room_id,
        "name": data.name,
        "host_id": user["id"],
        "host_username": user["username"],
        "players": [{
            "id": user["id"],
            "username": user["username"],
            "avatar_color": user["avatar_color"],
            "score": 0,
            "is_ready": True,
            "current_answer": None
        }],
        "question_count": data.question_count,
        "status": "waiting",
        "current_question_index": 0,
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    
    await db.rooms.insert_one(room)
    
    # Remove _id for JSON serialization before broadcast
    room.pop('_id', None)
    
    # Broadcast to all clients that a new room is available
    try:
        await sio.emit('rooms:updated', {"action": "created", "room": room})
    except Exception as e:
        logger.error(f"Error broadcasting room creation: {e}")
    
    return RoomResponse(**room)

@api_router.post("/rooms/{room_id}/join", response_model=RoomResponse)
async def join_room(room_id: str, user: dict = Depends(get_current_user)):
    room = await db.rooms.find_one({"id": room_id})
    if not room:
        raise HTTPException(status_code=404, detail="Oda bulunamadi")
    
    if room["status"] != "waiting":
        raise HTTPException(status_code=400, detail="Bu oda zaten oyunda")
    
    if len(room["players"]) >= 2:
        raise HTTPException(status_code=400, detail="Oda dolu")
    
    if any(p["id"] == user["id"] for p in room["players"]):
        raise HTTPException(status_code=400, detail="Zaten bu odadasiniz")
    
    new_player = {
        "id": user["id"],
        "username": user["username"],
        "avatar_color": user["avatar_color"],
        "score": 0,
        "is_ready": False,
        "current_answer": None
    }
    
    await db.rooms.update_one(
        {"id": room_id},
        {"$push": {"players": new_player}}
    )
    
    room = await db.rooms.find_one({"id": room_id})
    
    # Remove _id for JSON serialization
    room.pop('_id', None)
    
    # Broadcast room update to all users in the room
    try:
        await sio.emit('room:updated', room, room=room_id)
        await sio.emit('rooms:updated', {"action": "player_joined", "room": room})
    except Exception as e:
        logger.error(f"Error broadcasting room join: {e}")
    
    return RoomResponse(**room)

@api_router.post("/rooms/{room_id}/leave")
async def leave_room(room_id: str, user: dict = Depends(get_current_user)):
    room = await db.rooms.find_one({"id": room_id})
    if not room:
        raise HTTPException(status_code=404, detail="Oda bulunamadi")
    
    # Remove player from room
    await db.rooms.update_one(
        {"id": room_id},
        {"$pull": {"players": {"id": user["id"]}}}
    )
    
    # If host left, delete room or transfer ownership
    if room["host_id"] == user["id"]:
        remaining_players = [p for p in room["players"] if p["id"] != user["id"]]
        if remaining_players:
            # Transfer ownership
            await db.rooms.update_one(
                {"id": room_id},
                {
                    "$set": {
                        "host_id": remaining_players[0]["id"],
                        "host_username": remaining_players[0]["username"]
                    }
                }
            )
        else:
            # Delete room
            await db.rooms.delete_one({"id": room_id})
    
    return {"message": "Odadan ayrildiniz"}

# =========================
# Category Endpoints
# =========================

@api_router.get("/categories")
async def get_categories():
    categories_with_count = []
    for cat in CATEGORIES:
        count = await db.questions.count_documents({"category": cat["name"]})
        categories_with_count.append({
            **cat,
            "question_count": count
        })
    return categories_with_count

# =========================
# Question Endpoints
# =========================

@api_router.get("/questions", response_model=List[QuestionResponse])
async def get_questions(category: Optional[str] = None, user: dict = Depends(get_current_user)):
    query = {}
    if category:
        query["category"] = category
    
    questions = await db.questions.find(query).to_list(100)
    return [QuestionResponse(**q) for q in questions]

@api_router.post("/questions", response_model=QuestionResponse)
async def add_question(data: QuestionCreate, user: dict = Depends(get_admin_user)):
    """Admin only - Add a new question"""
    question_id = str(uuid.uuid4())
    question = {
        "id": question_id,
        "category": data.category,
        "question": data.question,
        "options": data.options,
        "correct_answer": data.correct_answer,
        "is_ai_generated": False,
        "created_by": user["id"],
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    
    await db.questions.insert_one(question)
    return QuestionResponse(**question)

@api_router.post("/questions/generate", response_model=List[QuestionResponse])
async def generate_ai_questions(data: GenerateQuestionsRequest, user: dict = Depends(get_admin_user)):
    """Admin only - Generate questions using AI"""
    try:
        client = OpenAI(
            api_key=EMERGENT_LLM_KEY,
            base_url="https://api.emergentagi.com/v1"
        )
        
        prompt = f"""Generate {data.count} multiple choice trivia questions in Turkish for the category "{data.category}".

Each question must have:
- A clear question text in Turkish
- Exactly 4 options (A, B, C, D)
- The index of the correct answer (0, 1, 2, or 3)

Return as JSON array with this exact format:
[
  {{
    "question": "Soru metni?",
    "options": ["A secenegi", "B secenegi", "C secenegi", "D secenegi"],
    "correct_answer": 0
  }}
]

Make sure questions are diverse, interesting, and factually correct.
Only return the JSON array, nothing else."""

        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "You are a trivia question generator. Always respond with valid JSON only."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.8,
            max_tokens=2000
        )
        
        import json
        content = response.choices[0].message.content.strip()
        # Clean potential markdown code blocks
        if content.startswith("```"):
            content = content.split("```")[1]
            if content.startswith("json"):
                content = content[4:]
        
        questions_data = json.loads(content)
        
        generated_questions = []
        for q in questions_data:
            question_id = str(uuid.uuid4())
            question = {
                "id": question_id,
                "category": data.category,
                "question": q["question"],
                "options": q["options"],
                "correct_answer": q["correct_answer"],
                "is_ai_generated": True,
                "created_by": user["id"],
                "created_at": datetime.now(timezone.utc).isoformat()
            }
            await db.questions.insert_one(question)
            generated_questions.append(QuestionResponse(**question))
        
        return generated_questions
        
    except Exception as e:
        logger.error(f"AI question generation error: {e}")
        raise HTTPException(status_code=500, detail=f"Soru uretimi basarisiz: {str(e)}")

# =========================
# Leaderboard Endpoints
# =========================

@api_router.get("/leaderboard", response_model=List[UserResponse])
async def get_leaderboard():
    users = await db.users.find().sort("score", -1).to_list(100)
    return [UserResponse(
        id=u["id"],
        username=u["username"],
        email=u["email"],
        score=u["score"],
        friends=u.get("friends", []),
        avatar_color=u["avatar_color"],
        is_admin=u.get("email", "") in ADMIN_EMAILS,
        created_at=u["created_at"]
    ) for u in users]

# =========================
# Socket.IO Events
# =========================

# Track online users and their socket IDs
online_users = {}  # user_id -> sid
user_rooms = {}    # sid -> room_id
active_games = {}  # room_id -> game state

@sio.event
async def connect(sid, environ, auth):
    logger.info(f"Client connected: {sid}")
    
    # Authenticate user
    if auth and 'token' in auth:
        user_id = verify_token(auth['token'])
        if user_id:
            online_users[user_id] = sid
            await sio.save_session(sid, {'user_id': user_id})
            logger.info(f"User {user_id} authenticated")

@sio.event
async def disconnect(sid):
    logger.info(f"Client disconnected: {sid}")
    
    session = await sio.get_session(sid)
    if session:
        user_id = session.get('user_id')
        if user_id and user_id in online_users:
            del online_users[user_id]
        
        # Leave any room
        if sid in user_rooms:
            room_id = user_rooms[sid]
            del user_rooms[sid]
            await handle_player_leave(room_id, user_id)

@sio.event
async def room_join(sid, data):
    room_id = data.get('room_id')
    session = await sio.get_session(sid)
    user_id = session.get('user_id') if session else None
    
    if not user_id or not room_id:
        logger.warning(f"room_join failed: user_id={user_id}, room_id={room_id}")
        return
    
    # Join the Socket.IO room
    await sio.enter_room(sid, room_id)
    user_rooms[sid] = room_id
    
    logger.info(f"User {user_id} joined socket room {room_id}")
    
    # Get updated room from database and broadcast to all in room
    room = await db.rooms.find_one({"id": room_id})
    if room:
        # Remove _id for JSON serialization
        room.pop('_id', None)
        await sio.emit('room:updated', room, room=room_id)
        logger.info(f"Broadcasted room update to room {room_id}")

@sio.event
async def room_leave(sid, data):
    room_id = data.get('room_id')
    session = await sio.get_session(sid)
    user_id = session.get('user_id') if session else None
    
    if room_id:
        await sio.leave_room(sid, room_id)
        if sid in user_rooms:
            del user_rooms[sid]
        
        if user_id:
            await handle_player_leave(room_id, user_id)

@sio.event
async def room_ready(sid, data):
    room_id = data.get('room_id')
    ready = data.get('ready', False)
    session = await sio.get_session(sid)
    user_id = session.get('user_id') if session else None
    
    if not user_id or not room_id:
        logger.warning(f"room_ready failed: user_id={user_id}, room_id={room_id}")
        return
    
    logger.info(f"User {user_id} setting ready={ready} in room {room_id}")
    
    await db.rooms.update_one(
        {"id": room_id, "players.id": user_id},
        {"$set": {"players.$.is_ready": ready}}
    )
    
    room = await db.rooms.find_one({"id": room_id})
    if room:
        # Remove _id for JSON serialization
        room.pop('_id', None)
        await sio.emit('room:updated', room, room=room_id)
        logger.info(f"Broadcasted ready state update to room {room_id}")

@sio.event
async def game_start(sid, data):
    room_id = data.get('room_id')
    session = await sio.get_session(sid)
    user_id = session.get('user_id') if session else None
    
    logger.info(f"game_start called by user {user_id} for room {room_id}")
    
    if not room_id:
        logger.warning("game_start: no room_id provided")
        return
    
    room = await db.rooms.find_one({"id": room_id})
    if not room:
        logger.warning(f"game_start: room {room_id} not found")
        return
        
    if room["host_id"] != user_id:
        logger.warning(f"game_start: user {user_id} is not host of room {room_id}")
        await sio.emit('error', {"message": "Sadece oda kurucusu oyunu başlatabilir"}, to=sid)
        return
    
    if len(room["players"]) < 2:
        logger.warning(f"game_start: not enough players in room {room_id}")
        await sio.emit('error', {"message": "En az 2 oyuncu gerekli"}, to=sid)
        return
    
    # Check if all players are ready
    all_ready = all(p.get("is_ready", False) for p in room["players"])
    if not all_ready:
        logger.warning(f"game_start: not all players ready in room {room_id}")
        await sio.emit('error', {"message": "Tüm oyuncular hazır değil"}, to=sid)
        return
    
    # Get random questions
    questions = await db.questions.aggregate([
        {"$sample": {"size": room["question_count"]}}
    ]).to_list(room["question_count"])
    
    if len(questions) < room["question_count"]:
        logger.warning(f"game_start: not enough questions for room {room_id}")
        await sio.emit('error', {"message": "Yeterli soru yok"}, to=sid)
        return
    
    logger.info(f"Starting game in room {room_id} with {len(questions)} questions")
    
    # Update room status
    await db.rooms.update_one(
        {"id": room_id},
        {"$set": {"status": "playing"}}
    )
    
    # Initialize game state
    active_games[room_id] = {
        "questions": questions,
        "current_index": 0,
        "players": {p["id"]: {"score": 0, "answer": None} for p in room["players"]},
        "timer_task": None
    }
    
    # Start first question
    await send_question(room_id)

@sio.event
async def game_answer(sid, data):
    room_id = data.get('room_id')
    answer = data.get('answer')
    session = await sio.get_session(sid)
    user_id = session.get('user_id') if session else None
    
    logger.info(f"game_answer: user {user_id} answered {answer} in room {room_id}")
    
    if not user_id or room_id not in active_games:
        logger.warning(f"game_answer: invalid user_id or room not active")
        return
    
    game = active_games[room_id]
    
    # Check if already revealing (prevent late answers)
    if game.get("revealing"):
        logger.warning(f"game_answer: answer rejected, already revealing")
        return
    
    if user_id in game["players"]:
        # Check if player already answered
        if game["players"][user_id]["answer"] is not None:
            logger.warning(f"game_answer: user {user_id} already answered")
            return
        
        game["players"][user_id]["answer"] = answer
        
        # Update database
        await db.rooms.update_one(
            {"id": room_id, "players.id": user_id},
            {"$set": {"players.$.current_answer": answer}}
        )
        
        logger.info(f"Answer recorded for user {user_id}")
        
        # Check if all players answered
        all_answered = all(p["answer"] is not None for p in game["players"].values())
        if all_answered:
            logger.info(f"All players answered in room {room_id}, revealing early")
            if game.get("timer_task") and not game["timer_task"].done():
                game["timer_task"].cancel()
            await reveal_answer(room_id)

async def send_question(room_id: str):
    if room_id not in active_games:
        logger.warning(f"send_question: room {room_id} not in active_games")
        return
    
    game = active_games[room_id]
    questions = game["questions"]
    index = game["current_index"]
    
    if index >= len(questions):
        await end_game(room_id)
        return
    
    # Cancel any existing timer before starting new one
    if game.get("timer_task") and not game["timer_task"].done():
        game["timer_task"].cancel()
        try:
            await game["timer_task"]
        except asyncio.CancelledError:
            pass
    
    question = questions[index]
    room = await db.rooms.find_one({"id": room_id})
    
    if not room:
        logger.warning(f"send_question: room {room_id} not found in database")
        return
    
    # Reset answers for all players
    for player_id in game["players"]:
        game["players"][player_id]["answer"] = None
    
    await db.rooms.update_one(
        {"id": room_id},
        {"$set": {"players.$[].current_answer": None}}
    )
    
    logger.info(f"Sending question {index + 1}/{len(questions)} to room {room_id}")
    
    game_state = {
        "room_id": room_id,
        "current_question": {
            "id": question["id"],
            "category": question["category"],
            "question": question["question"],
            "options": question["options"],
            "correct_answer": -1  # Don't reveal answer yet
        },
        "question_index": index,
        "total_questions": len(questions),
        "time_remaining": 20,
        "players": [
            {
                "id": p["id"],
                "username": p["username"],
                "avatar_color": p["avatar_color"],
                "score": game["players"].get(p["id"], {}).get("score", 0),
                "is_ready": True,
                "current_answer": None
            }
            for p in room["players"]
        ],
        "status": "question",
        "correct_answer": None
    }
    
    await sio.emit('game:state', game_state, room=room_id)
    
    # Start timer
    game["timer_task"] = asyncio.create_task(question_timer(room_id))

async def question_timer(room_id: str):
    """Timer for each question - counts down from 20 to 0"""
    try:
        for remaining in range(19, -1, -1):
            await asyncio.sleep(1)
            
            # Check if game still exists
            if room_id not in active_games:
                logger.info(f"Timer stopped: room {room_id} no longer active")
                return
            
            # Emit timer update
            await sio.emit('game:timer', remaining, room=room_id)
        
        # Time's up - reveal answer
        logger.info(f"Timer finished for room {room_id}, revealing answer")
        await reveal_answer(room_id)
        
    except asyncio.CancelledError:
        logger.info(f"Timer cancelled for room {room_id}")
    except Exception as e:
        logger.error(f"Timer error for room {room_id}: {e}")

async def reveal_answer(room_id: str):
    if room_id not in active_games:
        logger.warning(f"reveal_answer: room {room_id} not in active_games")
        return
    
    game = active_games[room_id]
    
    # Prevent multiple reveals
    if game.get("revealing"):
        logger.warning(f"reveal_answer: already revealing for room {room_id}")
        return
    game["revealing"] = True
    
    questions = game["questions"]
    index = game["current_index"]
    question = questions[index]
    correct = question["correct_answer"]
    
    room = await db.rooms.find_one({"id": room_id})
    if not room:
        logger.warning(f"reveal_answer: room {room_id} not found")
        game["revealing"] = False
        return
    
    logger.info(f"Revealing answer for question {index + 1} in room {room_id}, correct: {correct}")
    
    # Calculate scores
    for player_id, player_data in game["players"].items():
        answer = player_data["answer"]
        if answer == correct:
            player_data["score"] += 5
            logger.info(f"Player {player_id} answered correctly, +5 points")
        elif answer is not None:
            player_data["score"] -= 3
            if player_data["score"] < 0:
                player_data["score"] = 0
            logger.info(f"Player {player_id} answered wrong, -3 points")
        else:
            logger.info(f"Player {player_id} did not answer")
    
    # Update room scores in database
    for player in room["players"]:
        new_score = game["players"].get(player["id"], {}).get("score", 0)
        await db.rooms.update_one(
            {"id": room_id, "players.id": player["id"]},
            {"$set": {"players.$.score": new_score}}
        )
    
    room = await db.rooms.find_one({"id": room_id})
    
    await sio.emit('game:answer_reveal', {
        "correct_answer": correct,
        "players": [
            {
                "id": p["id"],
                "username": p["username"],
                "avatar_color": p["avatar_color"],
                "score": game["players"].get(p["id"], {}).get("score", 0),
                "is_ready": True,
                "current_answer": game["players"].get(p["id"], {}).get("answer")
            }
            for p in room["players"]
        ]
    }, room=room_id)
    
    # Wait before next question
    await asyncio.sleep(3)
    
    # Reset revealing flag and move to next question
    game["revealing"] = False
    game["current_index"] += 1
    await send_question(room_id)

async def end_game(room_id: str):
    if room_id not in active_games:
        return
    
    game = active_games[room_id]
    room = await db.rooms.find_one({"id": room_id})
    
    # Update user scores in database
    for player in room["players"]:
        player_score = game["players"].get(player["id"], {}).get("score", 0)
        await db.users.update_one(
            {"id": player["id"]},
            {"$inc": {"score": player_score}}
        )
    
    # Mark room as finished
    await db.rooms.update_one(
        {"id": room_id},
        {"$set": {"status": "finished"}}
    )
    
    await sio.emit('game:finished', {
        "players": [
            {
                "id": p["id"],
                "username": p["username"],
                "avatar_color": p["avatar_color"],
                "score": game["players"].get(p["id"], {}).get("score", 0),
                "is_ready": True,
                "current_answer": None
            }
            for p in room["players"]
        ]
    }, room=room_id)
    
    # Cleanup
    del active_games[room_id]

async def handle_player_leave(room_id: str, user_id: str):
    room = await db.rooms.find_one({"id": room_id})
    if not room:
        return
    
    # Remove player
    await db.rooms.update_one(
        {"id": room_id},
        {"$pull": {"players": {"id": user_id}}}
    )
    
    # If game was active, end it
    if room_id in active_games:
        await end_game(room_id)
    
    await sio.emit('room:player_left', user_id, room=room_id)

@sio.event
async def rooms_list(sid):
    rooms = await db.rooms.find({"status": "waiting"}).to_list(50)
    await sio.emit('rooms:list', rooms, to=sid)

# Include the router in the main app
fastapi_app.include_router(api_router)

fastapi_app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@fastapi_app.on_event("startup")
async def startup_event():
    # Create indexes
    await db.users.create_index("email", unique=True)
    await db.users.create_index("username", unique=True)
    await db.rooms.create_index("status")
    await db.questions.create_index("category")
    
    # Add some sample questions if none exist
    count = await db.questions.count_documents({})
    if count == 0:
        sample_questions = [
            # Genel Kültür
            {
                "id": str(uuid.uuid4()),
                "category": "Genel Kültür",
                "question": "Türkiye'nin başkenti neresidir?",
                "options": ["İstanbul", "Ankara", "İzmir", "Bursa"],
                "correct_answer": 1,
                "is_ai_generated": False,
                "created_at": datetime.now(timezone.utc).isoformat()
            },
            {
                "id": str(uuid.uuid4()),
                "category": "Genel Kültür",
                "question": "Dünyanın en büyük okyanusu hangisidir?",
                "options": ["Atlantik", "Hint", "Pasifik", "Arktik"],
                "correct_answer": 2,
                "is_ai_generated": False,
                "created_at": datetime.now(timezone.utc).isoformat()
            },
            {
                "id": str(uuid.uuid4()),
                "category": "Genel Kültür",
                "question": "Dünyanın en kalabalık ülkesi hangisidir?",
                "options": ["Hindistan", "ABD", "Çin", "Endonezya"],
                "correct_answer": 2,
                "is_ai_generated": False,
                "created_at": datetime.now(timezone.utc).isoformat()
            },
            {
                "id": str(uuid.uuid4()),
                "category": "Genel Kültür",
                "question": "Güneş sistemindeki en büyük gezegen hangisidir?",
                "options": ["Satürn", "Jüpiter", "Uranüs", "Neptün"],
                "correct_answer": 1,
                "is_ai_generated": False,
                "created_at": datetime.now(timezone.utc).isoformat()
            },
            {
                "id": str(uuid.uuid4()),
                "category": "Genel Kültür",
                "question": "Nobel Barış Ödülü hangi şehirde verilir?",
                "options": ["Stockholm", "Oslo", "Helsinki", "Kopenhag"],
                "correct_answer": 1,
                "is_ai_generated": False,
                "created_at": datetime.now(timezone.utc).isoformat()
            },
            # Tarih
            {
                "id": str(uuid.uuid4()),
                "category": "Tarih",
                "question": "İstanbul'un fethi hangi yılda gerçekleşmiştir?",
                "options": ["1453", "1071", "1299", "1923"],
                "correct_answer": 0,
                "is_ai_generated": False,
                "created_at": datetime.now(timezone.utc).isoformat()
            },
            {
                "id": str(uuid.uuid4()),
                "category": "Tarih",
                "question": "Türkiye Cumhuriyeti hangi yılda kuruldu?",
                "options": ["1920", "1921", "1922", "1923"],
                "correct_answer": 3,
                "is_ai_generated": False,
                "created_at": datetime.now(timezone.utc).isoformat()
            },
            {
                "id": str(uuid.uuid4()),
                "category": "Tarih",
                "question": "Malazgirt Savaşı hangi yılda yapılmıştır?",
                "options": ["1071", "1176", "1243", "1402"],
                "correct_answer": 0,
                "is_ai_generated": False,
                "created_at": datetime.now(timezone.utc).isoformat()
            },
            {
                "id": str(uuid.uuid4()),
                "category": "Tarih",
                "question": "Osmanlı Devleti'nin kurucusu kimdir?",
                "options": ["Orhan Gazi", "Osman Gazi", "Fatih Sultan Mehmet", "Yavuz Sultan Selim"],
                "correct_answer": 1,
                "is_ai_generated": False,
                "created_at": datetime.now(timezone.utc).isoformat()
            },
            {
                "id": str(uuid.uuid4()),
                "category": "Tarih",
                "question": "Kurtuluş Savaşı'nın başkomutanı kimdir?",
                "options": ["İsmet İnönü", "Kazım Karabekir", "Mustafa Kemal Atatürk", "Fevzi Çakmak"],
                "correct_answer": 2,
                "is_ai_generated": False,
                "created_at": datetime.now(timezone.utc).isoformat()
            },
            # Coğrafya
            {
                "id": str(uuid.uuid4()),
                "category": "Coğrafya",
                "question": "Dünyanın en uzun nehri hangisidir?",
                "options": ["Amazon", "Nil", "Missisipi", "Yangtze"],
                "correct_answer": 1,
                "is_ai_generated": False,
                "created_at": datetime.now(timezone.utc).isoformat()
            },
            {
                "id": str(uuid.uuid4()),
                "category": "Coğrafya",
                "question": "Türkiye'nin en yüksek dağı hangisidir?",
                "options": ["Uludağ", "Erciyes", "Ağrı Dağı", "Kaçkar"],
                "correct_answer": 2,
                "is_ai_generated": False,
                "created_at": datetime.now(timezone.utc).isoformat()
            },
            {
                "id": str(uuid.uuid4()),
                "category": "Coğrafya",
                "question": "Avrupa'nın en büyük gölü hangisidir?",
                "options": ["Bodensee", "Balaton", "Ladoga", "Cenevre"],
                "correct_answer": 2,
                "is_ai_generated": False,
                "created_at": datetime.now(timezone.utc).isoformat()
            },
            {
                "id": str(uuid.uuid4()),
                "category": "Coğrafya",
                "question": "Hangi ülke hem Avrupa hem Asya'da toprak sahibidir?",
                "options": ["Rusya", "Yunanistan", "İran", "Mısır"],
                "correct_answer": 0,
                "is_ai_generated": False,
                "created_at": datetime.now(timezone.utc).isoformat()
            },
            {
                "id": str(uuid.uuid4()),
                "category": "Coğrafya",
                "question": "Karadeniz'e kıyısı olan ülke sayısı kaçtır?",
                "options": ["4", "5", "6", "7"],
                "correct_answer": 2,
                "is_ai_generated": False,
                "created_at": datetime.now(timezone.utc).isoformat()
            },
            # Bilim & Teknoloji
            {
                "id": str(uuid.uuid4()),
                "category": "Bilim & Teknoloji",
                "question": "Su molekülü hangi elementlerden oluşur?",
                "options": ["Karbon ve Oksijen", "Hidrojen ve Azot", "Hidrojen ve Oksijen", "Karbon ve Hidrojen"],
                "correct_answer": 2,
                "is_ai_generated": False,
                "created_at": datetime.now(timezone.utc).isoformat()
            },
            {
                "id": str(uuid.uuid4()),
                "category": "Bilim & Teknoloji",
                "question": "İnternet'in icadında önemli rol oynayan ARPANET hangi ülkede geliştirildi?",
                "options": ["İngiltere", "Almanya", "ABD", "Japonya"],
                "correct_answer": 2,
                "is_ai_generated": False,
                "created_at": datetime.now(timezone.utc).isoformat()
            },
            {
                "id": str(uuid.uuid4()),
                "category": "Bilim & Teknoloji",
                "question": "DNA'nın açılımı nedir?",
                "options": ["Deoksiribonükleik Asit", "Diribonükleik Asit", "Deoksiadenin Asit", "Dioksiadenin Asit"],
                "correct_answer": 0,
                "is_ai_generated": False,
                "created_at": datetime.now(timezone.utc).isoformat()
            },
            {
                "id": str(uuid.uuid4()),
                "category": "Bilim & Teknoloji",
                "question": "Işık hızı saniyede yaklaşık kaç kilometredir?",
                "options": ["100.000 km", "200.000 km", "300.000 km", "400.000 km"],
                "correct_answer": 2,
                "is_ai_generated": False,
                "created_at": datetime.now(timezone.utc).isoformat()
            },
            {
                "id": str(uuid.uuid4()),
                "category": "Bilim & Teknoloji",
                "question": "İnsan vücudunda en büyük organ hangisidir?",
                "options": ["Karaciğer", "Beyin", "Deri", "Akciğer"],
                "correct_answer": 2,
                "is_ai_generated": False,
                "created_at": datetime.now(timezone.utc).isoformat()
            },
            # Spor
            {
                "id": str(uuid.uuid4()),
                "category": "Spor",
                "question": "FIFA Dünya Kupası kaç yılda bir düzenlenir?",
                "options": ["2 yılda bir", "3 yılda bir", "4 yılda bir", "5 yılda bir"],
                "correct_answer": 2,
                "is_ai_generated": False,
                "created_at": datetime.now(timezone.utc).isoformat()
            },
            {
                "id": str(uuid.uuid4()),
                "category": "Spor",
                "question": "Basketbolda bir takım kaç oyuncudan oluşur?",
                "options": ["4", "5", "6", "7"],
                "correct_answer": 1,
                "is_ai_generated": False,
                "created_at": datetime.now(timezone.utc).isoformat()
            },
            {
                "id": str(uuid.uuid4()),
                "category": "Spor",
                "question": "Olimpiyat Oyunları ilk olarak hangi ülkede düzenlenmiştir?",
                "options": ["İtalya", "Fransa", "Yunanistan", "İspanya"],
                "correct_answer": 2,
                "is_ai_generated": False,
                "created_at": datetime.now(timezone.utc).isoformat()
            },
            {
                "id": str(uuid.uuid4()),
                "category": "Spor",
                "question": "Türkiye Süper Lig'de şampiyonluğu en çok kazanan takım hangisidir?",
                "options": ["Beşiktaş", "Fenerbahçe", "Galatasaray", "Trabzonspor"],
                "correct_answer": 2,
                "is_ai_generated": False,
                "created_at": datetime.now(timezone.utc).isoformat()
            },
            {
                "id": str(uuid.uuid4()),
                "category": "Spor",
                "question": "Tenis'te 'Grand Slam' turnuva sayısı kaçtır?",
                "options": ["2", "3", "4", "5"],
                "correct_answer": 2,
                "is_ai_generated": False,
                "created_at": datetime.now(timezone.utc).isoformat()
            },
            # Sanat & Edebiyat
            {
                "id": str(uuid.uuid4()),
                "category": "Sanat & Edebiyat",
                "question": "Mona Lisa tablosunun ressamı kimdir?",
                "options": ["Picasso", "Van Gogh", "Leonardo da Vinci", "Michelangelo"],
                "correct_answer": 2,
                "is_ai_generated": False,
                "created_at": datetime.now(timezone.utc).isoformat()
            },
            {
                "id": str(uuid.uuid4()),
                "category": "Sanat & Edebiyat",
                "question": "'Suç ve Ceza' romanının yazarı kimdir?",
                "options": ["Tolstoy", "Dostoyevski", "Çehov", "Gogol"],
                "correct_answer": 1,
                "is_ai_generated": False,
                "created_at": datetime.now(timezone.utc).isoformat()
            },
            {
                "id": str(uuid.uuid4()),
                "category": "Sanat & Edebiyat",
                "question": "Nobel Edebiyat Ödülü alan ilk Türk yazar kimdir?",
                "options": ["Yaşar Kemal", "Orhan Pamuk", "Nazım Hikmet", "Aziz Nesin"],
                "correct_answer": 1,
                "is_ai_generated": False,
                "created_at": datetime.now(timezone.utc).isoformat()
            },
            {
                "id": str(uuid.uuid4()),
                "category": "Sanat & Edebiyat",
                "question": "'Hamlet' kimin eseridir?",
                "options": ["Charles Dickens", "William Shakespeare", "Oscar Wilde", "Jane Austen"],
                "correct_answer": 1,
                "is_ai_generated": False,
                "created_at": datetime.now(timezone.utc).isoformat()
            },
            {
                "id": str(uuid.uuid4()),
                "category": "Sanat & Edebiyat",
                "question": "'Yıldız Gece' tablosunun ressamı kimdir?",
                "options": ["Monet", "Van Gogh", "Renoir", "Cezanne"],
                "correct_answer": 1,
                "is_ai_generated": False,
                "created_at": datetime.now(timezone.utc).isoformat()
            },
            # Müzik & Sinema
            {
                "id": str(uuid.uuid4()),
                "category": "Müzik & Sinema",
                "question": "Oscar ödüllü 'Titanic' filminin yönetmeni kimdir?",
                "options": ["Steven Spielberg", "James Cameron", "Christopher Nolan", "Martin Scorsese"],
                "correct_answer": 1,
                "is_ai_generated": False,
                "created_at": datetime.now(timezone.utc).isoformat()
            },
            {
                "id": str(uuid.uuid4()),
                "category": "Müzik & Sinema",
                "question": "Beatles grubunun memleketi neresidir?",
                "options": ["Londra", "Manchester", "Liverpool", "Birmingham"],
                "correct_answer": 2,
                "is_ai_generated": False,
                "created_at": datetime.now(timezone.utc).isoformat()
            },
            {
                "id": str(uuid.uuid4()),
                "category": "Müzik & Sinema",
                "question": "'Bohemian Rhapsody' şarkısı hangi gruba aittir?",
                "options": ["The Beatles", "Led Zeppelin", "Queen", "Pink Floyd"],
                "correct_answer": 2,
                "is_ai_generated": False,
                "created_at": datetime.now(timezone.utc).isoformat()
            },
            {
                "id": str(uuid.uuid4()),
                "category": "Müzik & Sinema",
                "question": "Yüzüklerin Efendisi üçlemesinin yönetmeni kimdir?",
                "options": ["George Lucas", "Peter Jackson", "James Cameron", "Steven Spielberg"],
                "correct_answer": 1,
                "is_ai_generated": False,
                "created_at": datetime.now(timezone.utc).isoformat()
            },
            {
                "id": str(uuid.uuid4()),
                "category": "Müzik & Sinema",
                "question": "Hangi Türk film en iyi yabancı film Oscar'ına aday gösterildi?",
                "options": ["Bir Zamanlar Anadolu'da", "Kış Uykusu", "Mustang", "Kuru Otlar Üstüne"],
                "correct_answer": 3,
                "is_ai_generated": False,
                "created_at": datetime.now(timezone.utc).isoformat()
            },
        ]
        await db.questions.insert_many(sample_questions)
        logger.info(f"Added {len(sample_questions)} sample questions")

@fastapi_app.on_event("shutdown")
async def shutdown_db_client():
    client.close()

# Run with socket app for socket.io support
app = socketio.ASGIApp(sio, fastapi_app)
