"""
Módulo de autenticação do ASPM Platform.

Responsável por:
- Hash e verificação de senha (bcrypt).
- Geração e verificação de um token de sessão assinado (HMAC-SHA256),
  análogo a um JWT simplificado, armazenado em cookie no navegador.
- Funções de alto nível de cadastro, login e logout, integradas ao
  Database/db.py (SQLite) e ao streamlit_cookies_controller.

Implementação manual (sem streamlit-authenticator) por escolha
deliberada: reduz dependências externas e mantém o fluxo de
autenticação — a parte mais sensível do sistema — totalmente auditável
linha a linha.
"""

import os
import time
import json
import hmac
import hashlib
import base64
import re

import bcrypt
import streamlit as st
from streamlit_cookies_controller import CookieController

from Database.db import (
    criar_usuario,
    buscar_usuario_por_username,
    buscar_usuario_por_id,
)

COOKIE_NAME = "aspm_session"
COOKIE_EXPIRY_DAYS = 7

# Chave usada para assinar o token de sessão. Em produção, DEVE vir de
# variável de ambiente (ex: definida no .env / secrets do compose).
# Se não definida, gera uma chave aleatória por processo — isso invalida
# sessões existentes a cada restart do app, o que é aceitável para
# ambiente de desenvolvimento, mas deve ser configurado explicitamente
# em qualquer ambiente que precise persistir sessões entre restarts.
SESSION_SECRET = os.environ.get("SESSION_SECRET") or base64.urlsafe_b64encode(os.urandom(32)).decode()

_EMAIL_REGEX = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


# =====================================
# HASH DE SENHA
# =====================================

def gerar_hash_senha(senha: str) -> str:
    """Gera o hash bcrypt de uma senha em texto plano."""
    return bcrypt.hashpw(senha.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

def verificar_senha(senha: str, senha_hash: str) -> bool:
    """Verifica se a senha em texto plano corresponde ao hash armazenado."""
    try:
        return bcrypt.checkpw(senha.encode("utf-8"), senha_hash.encode("utf-8"))
    except (ValueError, TypeError):
        # Hash corrompido/incompatível — trata como senha incorreta,
        # nunca levanta exceção para o chamador.
        return False


# =====================================
# TOKEN DE SESSÃO (HMAC, formato similar a JWT)
# =====================================

def _b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def _b64decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)

def _assinar_token(payload: dict) -> str:
    payload_json = json.dumps(payload, separators=(",", ":")).encode()
    payload_b64 = _b64encode(payload_json)
    assinatura = hmac.new(
        SESSION_SECRET.encode(), payload_b64.encode(), hashlib.sha256
    ).digest()
    assinatura_b64 = _b64encode(assinatura)
    return f"{payload_b64}.{assinatura_b64}"

def _verificar_token(token: str):
    """Retorna o payload do token se válido e não expirado, senão None."""
    try:
        payload_b64, assinatura_b64 = token.split(".")
    except (ValueError, AttributeError):
        return None

    esperado = hmac.new(
        SESSION_SECRET.encode(), payload_b64.encode(), hashlib.sha256
    ).digest()
    esperado_b64 = _b64encode(esperado)

    if not hmac.compare_digest(esperado_b64, assinatura_b64):
        return None

    try:
        payload = json.loads(_b64decode(payload_b64))
    except (ValueError, json.JSONDecodeError):
        return None

    if payload.get("exp", 0) < time.time():
        return None

    return payload

def _gerar_token_sessao(usuario_id: int, username: str) -> str:
    payload = {
        "usuario_id": usuario_id,
        "username": username,
        "exp": time.time() + (COOKIE_EXPIRY_DAYS * 86400),
    }
    return _assinar_token(payload)


# =====================================
# VALIDAÇÃO DE ENTRADA
# =====================================

def validar_username(username: str) -> str | None:
    if not username or len(username) < 3:
        return "Usuário deve ter ao menos 3 caracteres."
    if not re.match(r"^[a-zA-Z0-9_.-]+$", username):
        return "Usuário deve conter apenas letras, números, '.', '_' ou '-'."
    return None

def validar_email(email: str) -> str | None:
    if not email or not _EMAIL_REGEX.match(email):
        return "E-mail inválido."
    return None

def validar_senha(senha: str) -> str | None:
    if not senha or len(senha) < 8:
        return "Senha deve ter ao menos 8 caracteres."
    return None


# =====================================
# CONTROLE DE SESSÃO (Streamlit + cookie)
# =====================================

def _get_cookie_controller() -> CookieController:
    """
    Garante uma única instância do CookieController por sessão Streamlit,
    evitando recriar o componente em cada rerun.
    """
    if "_cookie_controller" not in st.session_state:
        st.session_state["_cookie_controller"] = CookieController()
    return st.session_state["_cookie_controller"]

def cadastrar_usuario(username: str, email: str, senha: str, nome: str):
    """
    Valida e cria um novo usuário. Retorna (sucesso: bool, mensagem: str).
    """
    erro = validar_username(username) or validar_email(email) or validar_senha(senha)
    if erro:
        return False, erro

    senha_hash = gerar_hash_senha(senha)
    usuario_id = criar_usuario(username, email, senha_hash, nome)

    if usuario_id is None:
        return False, "Usuário ou e-mail já cadastrado."

    return True, "Cadastro realizado com sucesso! Faça login para continuar."

def autenticar(username: str, senha: str):
    """
    Verifica credenciais. Em caso de sucesso, grava o cookie de sessão e
    retorna (sucesso: bool, mensagem: str).
    """
    usuario = buscar_usuario_por_username(username)
    if usuario is None:
        return False, "Usuário ou senha inválidos."

    usuario_id, db_username, email, senha_hash, nome = usuario

    if not verificar_senha(senha, senha_hash):
        return False, "Usuário ou senha inválidos."

    token = _gerar_token_sessao(usuario_id, db_username)
    controller = _get_cookie_controller()
    controller.set(COOKIE_NAME, token)

    st.session_state["usuario_id"] = usuario_id
    st.session_state["username"] = db_username
    st.session_state["nome"] = nome

    return True, "Login realizado com sucesso!"

def logout():
    """Remove o cookie de sessão e limpa o estado local."""
    controller = _get_cookie_controller()
    controller.remove(COOKIE_NAME)
    for chave in ("usuario_id", "username", "nome"):
        st.session_state.pop(chave, None)

def usuario_logado():
    """
    Retorna o dict {usuario_id, username, nome} do usuário autenticado,
    ou None se não houver sessão válida. Verifica primeiro o
    st.session_state (rápido, evita refazer a query a cada rerun) e,
    se ausente, tenta restaurar a sessão a partir do cookie persistente.
    """
    if "usuario_id" in st.session_state:
        return {
            "usuario_id": st.session_state["usuario_id"],
            "username": st.session_state["username"],
            "nome": st.session_state["nome"],
        }

    controller = _get_cookie_controller()
    token = controller.get(COOKIE_NAME)
    if not token:
        return None

    payload = _verificar_token(token)
    if payload is None:
        return None

    usuario = buscar_usuario_por_id(payload["usuario_id"])
    if usuario is None:
        return None

    usuario_id, db_username, email, senha_hash, nome = usuario
    st.session_state["usuario_id"] = usuario_id
    st.session_state["username"] = db_username
    st.session_state["nome"] = nome

    return {"usuario_id": usuario_id, "username": db_username, "nome": nome}