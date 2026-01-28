from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from contextlib import asynccontextmanager
from typing import Annotated
from jose import JWTError, jwt
from passlib.context import CryptContext
import psycopg
from datetime import datetime, timedelta
from pydantic import BaseModel
import os
from dotenv import load_dotenv

load_dotenv()

# =============================
# VARIÁVEIS DE AMBIENTE (OBRIGATÓRIAS)
# =============================
SECRET_KEY = os.getenv("SECRET_KEY")
MASTER_KEY = os.getenv("MASTER_KEY")
DATABASE_URL = os.getenv("DATABASE_URL")

if not SECRET_KEY or not MASTER_KEY or not DATABASE_URL:
    raise RuntimeError("Variáveis de ambiente não configuradas.")

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# =============================
# MODELOS
# =============================
class UsuarioCreate(BaseModel):
    username: str
    senha: str
    master_key: str

# =============================
# CONEXÃO COM BANCO (RENDER USA SSL)
# =============================
def conectar_bd():
    return psycopg.connect(DATABASE_URL, sslmode="require")

# =============================
# LIFESPAN — CRIA TABELAS
# =============================
@asynccontextmanager
async def lifespan(app: FastAPI):
    conn = conectar_bd()
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS aluno (
            id SERIAL PRIMARY KEY,
            nome VARCHAR(100),
            semestre INT,
            curso VARCHAR(100)
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS usuario (
            id SERIAL PRIMARY KEY,
            username VARCHAR(50) UNIQUE,
            senha_hash VARCHAR(200)
        )
    """)

    conn.commit()
    conn.close()
    print("Banco pronto.")
    yield
    print("API encerrando.")

app = FastAPI(lifespan=lifespan)

# =============================
# SEGURANÇA
# =============================
def verificar_senha(senha_plana, senha_hash):
    return pwd_context.verify(senha_plana, senha_hash)

def gerar_hash_senha(senha):
    return pwd_context.hash(senha)

def criar_token(dados: dict):
    dados_copia = dados.copy()
    expira = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    dados_copia.update({"exp": expira})
    return jwt.encode(dados_copia, SECRET_KEY, algorithm=ALGORITHM)

def obter_usuario(username: str):
    conn = conectar_bd()
    cur = conn.cursor()
    cur.execute("SELECT username, senha_hash FROM usuario WHERE username=%s", (username,))
    user = cur.fetchone()
    conn.close()
    return user

def usuario_logado(token: Annotated[str, Depends(oauth2_scheme)]):
    cred_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Token inválido",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise cred_exception
    except JWTError:
        raise cred_exception
    return username

# =============================
# AUTENTICAÇÃO
# =============================
@app.post("/registrar")
def registrar(usuario: UsuarioCreate):

    if usuario.master_key != MASTER_KEY:
        raise HTTPException(status_code=403, detail="Chave mestra inválida")

    conn = conectar_bd()
    cur = conn.cursor()
    senha_hash = gerar_hash_senha(usuario.senha)

    try:
        cur.execute(
            "INSERT INTO usuario (username, senha_hash) VALUES (%s, %s)",
            (usuario.username, senha_hash)
        )
        conn.commit()
        return {"msg": "Usuário criado com sucesso"}

    except psycopg.errors.UniqueViolation:
        conn.rollback()
        raise HTTPException(status_code=400, detail="Usuário já existe")

    finally:
        conn.close()

@app.post("/login")
def login(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]):
    user = obter_usuario(form_data.username)
    if not user or not verificar_senha(form_data.password, user[1]):
        raise HTTPException(status_code=400, detail="Login inválido")

    token = criar_token({"sub": user[0]})
    return {"access_token": token, "token_type": "bearer"}

# =============================
# CRUD ALUNOS (PROTEGIDO)
# =============================
@app.get("/alunos")
def listar_alunos(user: str = Depends(usuario_logado)):
    conn = conectar_bd()
    cur = conn.cursor()
    cur.execute("SELECT * FROM aluno ORDER BY id")
    dados = cur.fetchall()
    conn.close()
    return [{"id": d[0], "nome": d[1], "semestre": d[2], "curso": d[3]} for d in dados]

@app.post("/alunos")
def criar_aluno(nome: str, semestre: int, curso: str, user: str = Depends(usuario_logado)):
    conn = conectar_bd()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO aluno (nome, semestre, curso) VALUES (%s, %s, %s)",
        (nome, semestre, curso)
    )
    conn.commit()
    conn.close()
    return {"msg": "Aluno criado"}

@app.put("/alunos/{aluno_id}")
def atualizar_aluno(
    aluno_id: int,
    nome: str | None = None,
    semestre: int | None = None,
    curso: str | None = None,
    user: str = Depends(usuario_logado)
):
    conn = conectar_bd()
    cur = conn.cursor()

    campos, valores = [], []

    if nome is not None:
        campos.append("nome=%s")
        valores.append(nome)
    if semestre is not None:
        campos.append("semestre=%s")
        valores.append(semestre)
    if curso is not None:
        campos.append("curso=%s")
        valores.append(curso)

    if not campos:
        raise HTTPException(status_code=400, detail="Nada para atualizar")

    valores.append(aluno_id)
    cur.execute(f"UPDATE aluno SET {', '.join(campos)} WHERE id=%s", tuple(valores))
    conn.commit()
    conn.close()
    return {"msg": "Aluno atualizado"}

@app.delete("/alunos/{aluno_id}")
def deletar_aluno(aluno_id: int, user: str = Depends(usuario_logado)):
    conn = conectar_bd()
    cur = conn.cursor()
    cur.execute("DELETE FROM aluno WHERE id=%s", (aluno_id,))
    conn.commit()
    conn.close()
    return {"msg": "Aluno removido"}
