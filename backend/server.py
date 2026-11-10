import asyncio
import base64
import json
import logging
import os
import re
import unicodedata
import uuid
from contextlib import suppress
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, List, Optional

import bcrypt
from fastapi import APIRouter, Depends, FastAPI, HTTPException, Query, Header
from dotenv import load_dotenv
from emergentintegrations.llm.chat import ImageContent, LlmChat, StreamDone, TextDelta, UserMessage
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
from pymongo import ASCENDING, DESCENDING, IndexModel
from pydantic import BaseModel, Field
import jwt


ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# One entry per collection: every field a route filters, sorts or dedupes on. Add the index in the same edit as the query.
INDEXES: dict[str, list[IndexModel]] = {
    "status_checks": [
        IndexModel([("id", ASCENDING)], name="id", unique=True),
        IndexModel([("timestamp", DESCENDING)], name="timestamp_desc"),
    ],
    "users": [IndexModel([("email", ASCENDING)], name="email_unique", unique=True)],
    "incidents": [
        IndexModel([("id", ASCENDING)], name="incident_id", unique=True),
        IndexModel([("created_at", DESCENDING)], name="incident_created_at"),
    ],
    "library": [IndexModel([("id", ASCENDING)], name="library_id", unique=True)],
    "analysis_history": [
        IndexModel([("id", ASCENDING)], name="analysis_history_id", unique=True),
        IndexModel([("owner_id", ASCENDING), ("created_at", DESCENDING)], name="analysis_history_owner_date"),
    ],
}


async def ensure_indexes() -> None:
    for collection, models in INDEXES.items():
        for model in models:  # one at a time so a bad spec skips only itself
            try:
                await db[collection].create_indexes([model])
            except Exception as exc:  # never block boot on an index; the log line names what to fix
                logging.getLogger(__name__).error("ensure_indexes(%s.%s): %s", collection, model.document["name"], exc)


async def seed_library() -> None:
    if await db.library.count_documents({}):
        return
    await db.library.insert_many([
        {"id": "mitre-attack", "order": 1, "title": "MITRE ATT&CK em 15 minutos", "category": "Fundamentos", "duration": "15 min", "level": "Essencial", "summary": "Como mapear técnicas, táticas e procedimentos observados em um incidente."},
        {"id": "phishing-triage", "order": 2, "title": "Triagem de phishing", "category": "Resposta", "duration": "12 min", "level": "Prático", "summary": "Sinais de engenharia social, validação de remetente e preservação de evidências."},
        {"id": "log-basics", "order": 3, "title": "Leitura de logs para blue team", "category": "Telemetria", "duration": "18 min", "level": "Intermediário", "summary": "Contexto, baseline e correlação antes de classificar um evento como ameaça."},
        {"id": "incident-comms", "order": 4, "title": "Comunicação durante incidentes", "category": "Operação", "duration": "10 min", "level": "Essencial", "summary": "Como escrever atualizações objetivas sem perder rastreabilidade ou contexto."},
    ])

# Create the main app without a prefix
app = FastAPI()

# Probe endpoint for the deployer and pod health checks: root-level (not /api), no DB call.
@app.get("/health", include_in_schema=False)
@app.head("/health", include_in_schema=False)
async def health():
    return {"status": "ok"}

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")


# Define Models
class StatusCheck(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    client_name: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class StatusCheckCreate(BaseModel):
    client_name: str


class AuthRequest(BaseModel):
    email: str
    password: str
    name: Optional[str] = None


class AuthResponse(BaseModel):
    token: str
    user: dict[str, Any]


class IncidentCreate(BaseModel):
    title: str = Field(min_length=3, max_length=120)
    source: str = Field(default="Manual")
    description: str = Field(default="")
    raw_logs: str = Field(default="")


class AnalysisRequest(BaseModel):
    context: str = Field(default="")
    image_base64: Optional[str] = None


class ReviewRequest(BaseModel):
    report: str


class EvidenceRequest(BaseModel):
    kind: str = Field(default="Note")
    content: str = Field(min_length=1)


class ChatRequest(BaseModel):
    question: str = Field(min_length=2, max_length=4000)
    incident_context: Optional[str] = None


JWT_SECRET = os.getenv("JWT_SECRET", "soc-sentinel-local-secret-change-me-32")
JWT_ALGORITHM = "HS256"
AI_MODEL = "gpt-5.6-terra"


def public_user(doc: dict[str, Any]) -> dict[str, Any]:
    return {"id": doc["id"], "email": doc["email"], "name": doc.get("name", "Analista")}


def create_token(user_id: str) -> str:
    return jwt.encode({"sub": user_id, "exp": int(datetime.now(timezone.utc).timestamp()) + 60 * 60 * 24 * 7}, JWT_SECRET, algorithm=JWT_ALGORITHM)


async def current_user(authorization: Optional[str] = Header(default=None)) -> dict[str, Any]:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Token ausente")
    try:
        payload = jwt.decode(authorization[7:], JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user = await db.users.find_one({"id": payload.get("sub")}, {"_id": 0})
    except Exception as exc:
        logging.getLogger(__name__).warning("invalid auth token: %s", exc)
        raise HTTPException(status_code=401, detail="Sessão inválida") from exc
    if not user:
        raise HTTPException(status_code=401, detail="Usuário não encontrado")
    return user


def incident_payload(title: str, source: str, description: str, raw_logs: str, user_id: str) -> dict[str, Any]:
    now = datetime.now(timezone.utc).isoformat()
    return {
        "id": str(uuid.uuid4()),
        "owner_id": user_id,
        "title": title,
        "source": source,
        "description": description,
        "raw_logs": raw_logs,
        "status": "open",
        "severity": "yellow",
        "severity_label": "Revisar",
        "analysis": None,
        "report": "",
        "report_reviewed": False,
        "checklist": [
            {"id": "contain", "label": "Conter o vetor ou ativo afetado", "done": False},
            {"id": "scope", "label": "Delimitar escopo e linha do tempo", "done": False},
            {"id": "evidence", "label": "Preservar evidências relevantes", "done": False},
            {"id": "recover", "label": "Validar recuperação e monitoramento", "done": False},
        ],
        "evidence": [],
        "created_at": now,
        "updated_at": now,
    }


def extract_json(text: str) -> dict[str, Any]:
    cleaned = re.sub(r"```(?:json)?", "", text, flags=re.IGNORECASE).replace("```", "").strip()
    try:
        value = json.loads(cleaned)
        return value if isinstance(value, dict) else {}
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", cleaned, flags=re.DOTALL)
        if match:
            try:
                value = json.loads(match.group(0))
                return value if isinstance(value, dict) else {}
            except json.JSONDecodeError:
                pass
    return {"summary": text.strip()}


def llm_safe_text(value: str) -> str:
    """Keep the provider request ASCII-safe while preserving technical content."""
    return unicodedata.normalize("NFKD", value).encode("ascii", "ignore").decode("ascii")


def configured_ai_key() -> Optional[str]:
    own_key = os.getenv("OPENAI_API_KEY", "")
    universal_key = os.getenv("EMERGENT_LLM_KEY", "")
    if own_key and len(own_key) > 20 and all(ord(char) < 128 for char in own_key):
        return own_key
    return universal_key or None


async def run_ai_analysis(incident: dict[str, Any], request: AnalysisRequest) -> dict[str, Any]:
    api_key = configured_ai_key()
    if not api_key:
        raise HTTPException(status_code=503, detail="Agente de IA não configurado")
    prompt = llm_safe_text(f"""Analyze this security incident for a blue team analyst. Be defensible, cite uncertainty, and never treat your output as a final decision.
Retorne SOMENTE JSON válido com as chaves: classification (green|yellow|red), classification_label, confidence (0-100), summary, findings (array de strings), next_steps (array de strings), report_draft.
Incidente: {incident['title']}
Descrição: {incident.get('description', '')}
Logs: {incident.get('raw_logs', '')}
Contexto adicional: {request.context}
Semáforo: green=aparentemente normal/baixo risco, yellow=precisa ser olhado, red=muito suspeito ou impacto potencial alto.
O rascunho precisa incluir escopo, evidências citadas, hipoteses e proximos passos, deixando claro que exige revisao humana. Responda em portugues.""")
    chat = LlmChat(
        api_key=api_key,
        session_id=f"incident-{incident['id']}-{uuid.uuid4()}",
        system_message="You are a SOC copilot. Do not invent evidence, do not claim certainty without data, and always require analyst review.",
    ).with_model("openai", AI_MODEL)
    contents = []
    if request.image_base64:
        encoded = request.image_base64.split(",", 1)[-1]
        try:
            base64.b64decode(encoded, validate=True)
            contents.append(ImageContent(image_base64=encoded))
        except (ValueError, TypeError):
            raise HTTPException(status_code=400, detail="Imagem em base64 inválida")
    answer = []
    async for event in chat.stream_message(UserMessage(text=prompt, file_contents=contents)):
        if isinstance(event, TextDelta):
            answer.append(event.content)
        elif isinstance(event, StreamDone):
            break
    result = extract_json("".join(answer))
    classification = str(result.get("classification", "yellow")).lower()
    if classification not in {"green", "yellow", "red"}:
        classification = "yellow"
    result["classification"] = classification
    result["classification_label"] = result.get("classification_label") or {"green": "Normal", "yellow": "Revisar", "red": "Suspeito"}[classification]
    result["confidence"] = max(0, min(100, int(result.get("confidence", 50))))
    result["findings"] = result.get("findings") if isinstance(result.get("findings"), list) else []
    result["next_steps"] = result.get("next_steps") if isinstance(result.get("next_steps"), list) else []
    return result


async def run_ai_question(question: str, incident_context: Optional[str] = None) -> str:
    api_key = configured_ai_key()
    if not api_key:
        raise HTTPException(status_code=503, detail="Agente de IA não configurado")
    prompt = llm_safe_text(f"Answer in Portuguese, objectively and cautiously, for a blue team analyst. Explain reasoning, separate facts from hypotheses, and suggest practical checks. Never recommend destructive actions without approval.\nQuestion: {question}\nContext: {incident_context or 'not provided'}")
    chat = LlmChat(api_key=api_key, session_id=f"copilot-{uuid.uuid4()}", system_message="You are an experienced SOC copilot. Help without replacing human review.").with_model("openai", AI_MODEL)
    answer = []
    async for event in chat.stream_message(UserMessage(text=prompt)):
        if isinstance(event, TextDelta):
            answer.append(event.content)
        elif isinstance(event, StreamDone):
            break
    return "".join(answer).strip()

# Add your routes to the router instead of directly to app
@api_router.get("/")
async def root():
    return {"message": "SOC Sentinel Blue API", "ai_model": AI_MODEL}


@api_router.post("/auth/register", response_model=AuthResponse)
async def register(input: AuthRequest):
    email = input.email.strip().lower()
    if len(input.password) < 8:
        raise HTTPException(status_code=400, detail="A senha precisa ter pelo menos 8 caracteres")
    if await db.users.find_one({"email": email}, {"_id": 0}):
        raise HTTPException(status_code=409, detail="E-mail já cadastrado")
    user = {"id": str(uuid.uuid4()), "email": email, "name": input.name or email.split("@")[0], "password_hash": bcrypt.hashpw(input.password.encode(), bcrypt.gensalt()).decode(), "created_at": datetime.now(timezone.utc).isoformat()}
    await db.users.insert_one(user)
    return AuthResponse(token=create_token(user["id"]), user=public_user(user))


@api_router.post("/auth/login", response_model=AuthResponse)
async def login(input: AuthRequest):
    user = await db.users.find_one({"email": input.email.strip().lower()}, {"_id": 0})
    if not user or not bcrypt.checkpw(input.password.encode(), user["password_hash"].encode()):
        raise HTTPException(status_code=401, detail="E-mail ou senha inválidos")
    return AuthResponse(token=create_token(user["id"]), user=public_user(user))


@api_router.get("/auth/me")
async def me(user: dict[str, Any] = Depends(current_user)):
    return public_user(user)


@api_router.get("/summary")
async def summary(user: dict[str, Any] = Depends(current_user)):
    docs = await db.incidents.find({"owner_id": user["id"]}, {"_id": 0, "severity": 1, "status": 1}).to_list(200)
    return {"total": len(docs), "open": sum(1 for d in docs if d.get("status") == "open"), "red": sum(1 for d in docs if d.get("severity") == "red"), "yellow": sum(1 for d in docs if d.get("severity") == "yellow"), "green": sum(1 for d in docs if d.get("severity") == "green")}


@api_router.get("/incidents")
async def list_incidents(user: dict[str, Any] = Depends(current_user)):
    return await db.incidents.find({"owner_id": user["id"]}, {"_id": 0}).sort("created_at", -1).limit(100).to_list(100)


@api_router.post("/incidents")
async def create_incident(input: IncidentCreate, user: dict[str, Any] = Depends(current_user)):
    doc = incident_payload(input.title, input.source, input.description, input.raw_logs, user["id"])
    await db.incidents.insert_one({**doc})
    return doc


@api_router.get("/incidents/{incident_id}")
async def get_incident(incident_id: str, user: dict[str, Any] = Depends(current_user)):
    doc = await db.incidents.find_one({"id": incident_id, "owner_id": user["id"]}, {"_id": 0})
    if not doc:
        raise HTTPException(status_code=404, detail="Incidente não encontrado")
    return doc


@api_router.post("/incidents/{incident_id}/analyze")
async def analyze_incident(incident_id: str, request: AnalysisRequest, user: dict[str, Any] = Depends(current_user)):
    incident = await db.incidents.find_one({"id": incident_id, "owner_id": user["id"]}, {"_id": 0})
    if not incident:
        raise HTTPException(status_code=404, detail="Incidente não encontrado")
    result = await run_ai_analysis(incident, request)
    now = datetime.now(timezone.utc).isoformat()
    await db.analysis_history.insert_one({"id": str(uuid.uuid4()), "owner_id": user["id"], "incident_id": incident_id, "incident_title": incident["title"], "created_at": now, "context": request.context, "analysis": result})
    await db.incidents.update_one({"id": incident_id}, {"$set": {"analysis": result, "report": result.get("report_draft", ""), "severity": result["classification"], "severity_label": result["classification_label"], "updated_at": now}})
    return {"incident_id": incident_id, **result, "requires_manual_review": True}


@api_router.post("/incidents/{incident_id}/review")
async def review_incident(incident_id: str, request: ReviewRequest, user: dict[str, Any] = Depends(current_user)):
    result = await db.incidents.update_one({"id": incident_id, "owner_id": user["id"]}, {"$set": {"report": request.report, "report_reviewed": True, "updated_at": datetime.now(timezone.utc).isoformat()}})
    if not result.matched_count:
        raise HTTPException(status_code=404, detail="Incidente não encontrado")
    return {"ok": True, "report_reviewed": True}


@api_router.post("/incidents/{incident_id}/checklist/{item_id}")
async def toggle_checklist(incident_id: str, item_id: str, user: dict[str, Any] = Depends(current_user)):
    incident = await db.incidents.find_one({"id": incident_id, "owner_id": user["id"]}, {"_id": 0})
    if not incident:
        raise HTTPException(status_code=404, detail="Incidente não encontrado")
    checklist = incident.get("checklist", [])
    for item in checklist:
        if item["id"] == item_id:
            item["done"] = not item.get("done", False)
    await db.incidents.update_one({"id": incident_id}, {"$set": {"checklist": checklist, "updated_at": datetime.now(timezone.utc).isoformat()}})
    return checklist


@api_router.post("/incidents/{incident_id}/evidence")
async def add_evidence(incident_id: str, request: EvidenceRequest, user: dict[str, Any] = Depends(current_user)):
    evidence = {"id": str(uuid.uuid4()), "kind": request.kind, "content": request.content, "created_at": datetime.now(timezone.utc).isoformat()}
    result = await db.incidents.update_one({"id": incident_id, "owner_id": user["id"]}, {"$push": {"evidence": evidence}, "$set": {"updated_at": datetime.now(timezone.utc).isoformat()}})
    if not result.matched_count:
        raise HTTPException(status_code=404, detail="Incidente não encontrado")
    return evidence


@api_router.get("/library")
async def library(user: dict[str, Any] = Depends(current_user)):
    return await db.library.find({}, {"_id": 0}).sort("order", 1).to_list(50)


@api_router.post("/ai/ask")
async def ask_ai(request: ChatRequest, user: dict[str, Any] = Depends(current_user)):
    return {"answer": await run_ai_question(request.question, request.incident_context)}


@api_router.get("/analysis-history")
async def analysis_history(user: dict[str, Any] = Depends(current_user)):
    return await db.analysis_history.find({"owner_id": user["id"]}, {"_id": 0}).sort("created_at", -1).limit(100).to_list(100)

@api_router.post("/status", response_model=StatusCheck)
async def create_status_check(input: StatusCheckCreate):
    status_dict = input.dict()
    status_obj = StatusCheck(**status_dict)
    _ = await db.status_checks.insert_one(status_obj.dict())
    return status_obj

@api_router.get("/status", response_model=List[StatusCheck])
async def get_status_checks(limit: int = Query(20, ge=1, le=100)):
    status_checks = await db.status_checks.find({}, {"_id": 0}).sort("timestamp", -1).limit(limit).to_list(limit)
    return [StatusCheck(**status_check) for status_check in status_checks]

# Include the router in the main app
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("startup")
async def start_index_build():
    app.state.index_task = asyncio.create_task(ensure_indexes())  # background: a big index build must not block boot
    app.state.seed_task = asyncio.create_task(seed_library())

@app.on_event("shutdown")
async def shutdown_db_client():
    app.state.index_task.cancel()  # stop a build still running before its client closes
    app.state.seed_task.cancel()
    with suppress(asyncio.CancelledError):
        await app.state.index_task
        await app.state.seed_task
    client.close()
