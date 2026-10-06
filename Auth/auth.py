# ASPM Platform - Application Security Posture Management (ASPM) platform that centralizes asset discovery, security scanning (SAST, DAST, SCA, IaC, CSPM, Secrets, DLP), and security findings, consolidating everything into a single application/business risk dashboard.
#
# Copyright (C) 2026 Guilherme Monteiro, Rafael Caruso, João Pedro
#
# SPDX-License-Identifier: GPL-3.0-or-later
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.

import os
import time
import json
import hmac
import hashlib
import base64
import re
import secrets
from datetime import datetime, timedelta, timezone

import bcrypt
import streamlit as st
import extra_streamlit_components as stx

from Database.db import (
    criar_usuario,
    buscar_usuario_por_username,
    buscar_usuario_por_id,
    registrar_log,
    salvar_codigo_mfa,
    validar_codigo_mfa,
    limpar_codigo_mfa,
)
from Auth.email_service import enviar_codigo_mfa

COOKIE_NAME        = "aspm_session"
COOKIE_EXPIRY_DAYS = 7

MFA_CODIGO_TAMANHO   = 6
MFA_EXPIRACAO_MINUTOS = 10

SESSION_SECRET = (
    os.environ.get("SESSION_SECRET")
    or base64.urlsafe_b64encode(os.urandom(32)).decode()
)

_EMAIL_REGEX   = re.compile(r"^[^@\s]+@[^@\s]+\.com$", re.IGNORECASE)
_SIMBOLO_REGEX = re.compile(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?`~]")


def gerar_hash_senha(senha: str) -> str:
    return bcrypt.hashpw(senha.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

def verificar_senha(senha: str, senha_hash: str) -> bool:
    try:
        return bcrypt.checkpw(senha.encode("utf-8"), senha_hash.encode("utf-8"))
    except (ValueError, TypeError):
        return False

def _b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def _b64decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)

def _assinar_token(payload: dict) -> str:
    payload_json = json.dumps(payload, separators=(",", ":")).encode()
    payload_b64  = _b64encode(payload_json)
    assinatura   = hmac.new(SESSION_SECRET.encode(), payload_b64.encode(), hashlib.sha256).digest()
    return f"{payload_b64}.{_b64encode(assinatura)}"

def _verificar_token(token: str):
    try:
        payload_b64, assinatura_b64 = token.split(".")
    except (ValueError, AttributeError):
        return None
    esperado = hmac.new(SESSION_SECRET.encode(), payload_b64.encode(), hashlib.sha256).digest()
    if not hmac.compare_digest(_b64encode(esperado), assinatura_b64):
        return None
    try:
        payload = json.loads(_b64decode(payload_b64))
    except (ValueError, json.JSONDecodeError):
        return None
    if payload.get("exp", 0) < time.time():
        return None
    return payload

def _gerar_token_sessao(usuario_id: int, username: str) -> str:
    return _assinar_token({
        "usuario_id": usuario_id,
        "username":   username,
        "exp":        time.time() + (COOKIE_EXPIRY_DAYS * 86400),
    })


def validar_username(username: str):
    if not username or len(username) < 3:
        return "Usuário deve ter ao menos 3 caracteres."
    if not re.match(r"^[a-zA-Z0-9_.-]+$", username):
        return "Usuário deve conter apenas letras, números, '.', '_' ou '-'."
    return None

def validar_email(email: str):
    if not email or not _EMAIL_REGEX.match(email):
        return "E-mail inválido. Use o formato usuario@dominio.com"
    return None

def validar_senha(senha: str):
    if not senha or len(senha) < 8:
        return "Senha deve ter ao menos 8 caracteres."
    if not re.search(r"[A-Z]", senha):
        return "Senha deve conter ao menos 1 letra maiúscula."
    if not _SIMBOLO_REGEX.search(senha):
        return "Senha deve conter ao menos 1 símbolo (ex: @, #, !, %)."
    return None


def _get_cookie_manager() -> stx.CookieManager:
    if "_cookie_manager" not in st.session_state:
        st.session_state["_cookie_manager"] = stx.CookieManager(key="aspm_cookie_manager")
    return st.session_state["_cookie_manager"]

def render_cookie_manager():
    cookie_manager = _get_cookie_manager()

    pendente = st.session_state.pop("_cookie_pending", None)
    if pendente is not None:
        token, expira = pendente
        cookie_manager.set(COOKIE_NAME, token, expires_at=expira)

    if st.session_state.get("_cookie_delete_pending"):
        try:
            cookie_manager.delete(COOKIE_NAME)
        except KeyError:
            pass


def cadastrar_usuario(username: str, email: str, senha: str, nome: str):
    erro = validar_username(username) or validar_email(email) or validar_senha(senha)
    if erro:
        return False, erro
    senha_hash = gerar_hash_senha(senha)
    usuario_id = criar_usuario(username, email, senha_hash, nome)
    if usuario_id is None:
        return False, "Usuário ou e-mail já cadastrado."
    registrar_log(
        usuario_id, nome or username,
        acao="Usuário Cadastrado",
        detalhe=f"Nova conta criada para {username}",
        nivel="INFORMATIVO",
        aplicacao="ASPM Platform",
        ambiente="Todos",
        origem="Auth Service"
    )
    return True, "Cadastro realizado com sucesso! Faça login para continuar."


# =====================================
# LOGIN - ETAPA 1: usuário e senha
# =====================================

def _gerar_codigo_mfa() -> str:
    return "".join(str(secrets.randbelow(10)) for _ in range(MFA_CODIGO_TAMANHO))

def _disparar_mfa(usuario_id: int, username: str, email: str, nome: str):
    codigo = _gerar_codigo_mfa()
    expira = datetime.now() + timedelta(minutes=MFA_EXPIRACAO_MINUTOS)
    salvar_codigo_mfa(usuario_id, codigo, expira)
    enviar_codigo_mfa(email, codigo)

    st.session_state["_mfa_usuario_id"] = usuario_id
    st.session_state["_mfa_username"]   = username
    st.session_state["_mfa_email"]      = email
    st.session_state["_mfa_nome"]       = nome

def autenticar(username: str, senha: str):
    """Etapa 1: valida usuário/senha e dispara o código MFA por e-mail."""
    usuario = buscar_usuario_por_username(username)
    if usuario is None:
        return False, "Usuário ou senha inválidos."
    usuario_id, db_username, email, senha_hash, nome, role = usuario
    if not verificar_senha(senha, senha_hash):
        return False, "Usuário ou senha inválidos."

    try:
        _disparar_mfa(usuario_id, db_username, email, nome)
    except RuntimeError as e:
        return False, f"Não foi possível enviar o código de verificação: {e}"

    registrar_log(
        usuario_id, nome or db_username,
        acao="Login - Senha Validada",
        detalhe=f"Código de verificação enviado para {db_username}",
        nivel="INFORMATIVO",
        aplicacao="ASPM Platform",
        ambiente="Todos",
        origem="Auth Service"
    )
    return True, f"Código de verificação enviado para o e-mail cadastrado."


# =====================================
# LOGIN - ETAPA 2: código MFA
# =====================================

def mfa_pendente() -> bool:
    return st.session_state.get("_mfa_usuario_id") is not None

def mfa_pendente_username():
    return st.session_state.get("_mfa_username")

def cancelar_mfa():
    usuario_id = st.session_state.get("_mfa_usuario_id")
    if usuario_id:
        limpar_codigo_mfa(usuario_id)
    for chave in ("_mfa_usuario_id", "_mfa_username", "_mfa_email", "_mfa_nome"):
        st.session_state.pop(chave, None)

def reenviar_mfa():
    usuario_id = st.session_state.get("_mfa_usuario_id")
    username   = st.session_state.get("_mfa_username")
    email      = st.session_state.get("_mfa_email")
    nome       = st.session_state.get("_mfa_nome")
    if not usuario_id:
        return False, "Sessão de verificação expirada. Faça login novamente."
    try:
        _disparar_mfa(usuario_id, username, email, nome)
    except RuntimeError as e:
        return False, f"Não foi possível reenviar o código: {e}"
    return True, "Novo código enviado para o seu e-mail."

def confirmar_mfa(codigo_digitado: str):
    """Etapa 2: valida o código informado e, se correto, completa o login."""
    usuario_id = st.session_state.get("_mfa_usuario_id")
    username   = st.session_state.get("_mfa_username")
    nome       = st.session_state.get("_mfa_nome")

    if not usuario_id:
        return False, "Sessão de verificação expirada. Faça login novamente."

    if not codigo_digitado or not codigo_digitado.isdigit():
        return False, "Informe o código de 6 dígitos recebido por e-mail."

    sucesso, mensagem = validar_codigo_mfa(usuario_id, codigo_digitado)
    if not sucesso:
        if "Faça login novamente" in mensagem:
            cancelar_mfa()
        return False, mensagem

    usuario_atualizado = buscar_usuario_por_id(usuario_id)
    role = usuario_atualizado[5] if usuario_atualizado else "usuario"

    token  = _gerar_token_sessao(usuario_id, username)
    expira = datetime.now(timezone.utc) + timedelta(days=COOKIE_EXPIRY_DAYS)

    st.session_state.pop("_cookie_delete_pending", None)
    st.session_state["_cookie_pending"] = (token, expira)

    st.session_state["usuario_id"] = usuario_id
    st.session_state["username"]   = username
    st.session_state["nome"]       = nome
    st.session_state["role"]       = role

    for chave in ("_mfa_usuario_id", "_mfa_username", "_mfa_email", "_mfa_nome"):
        st.session_state.pop(chave, None)

    registrar_log(
        usuario_id, nome or username,
        acao="Usuário Autenticado",
        detalhe=f"Login realizado com sucesso (MFA): {username}",
        nivel="INFORMATIVO",
        aplicacao="ASPM Platform",
        ambiente="Todos",
        origem="Auth Service"
    )
    return True, "Login realizado com sucesso!"


def logout():
    usuario_id = st.session_state.get("usuario_id")
    nome       = st.session_state.get("nome") or st.session_state.get("username", "")
    if usuario_id:
        registrar_log(
            usuario_id, nome,
            acao="Sessão Encerrada",
            detalhe="Logout realizado pelo usuário",
            nivel="INFORMATIVO",
            aplicacao="ASPM Platform",
            ambiente="Todos",
            origem="Auth Service"
        )
    for chave in list(st.session_state.keys()):
        if chave not in ("_cookie_manager",):
            st.session_state.pop(chave, None)
    st.session_state["_cookie_delete_pending"] = True
    st.rerun()

def usuario_logado():
    if st.session_state.get("_cookie_delete_pending"):
        return None

    if "usuario_id" in st.session_state:
        return {
            "usuario_id": st.session_state["usuario_id"],
            "username":   st.session_state["username"],
            "nome":       st.session_state["nome"],
            "role":       st.session_state.get("role", "usuario"),
        }

    token = st.context.cookies.get(COOKIE_NAME)
    if not token:
        return None

    payload = _verificar_token(token)
    if payload is None:
        return None

    usuario = buscar_usuario_por_id(payload["usuario_id"])
    if usuario is None:
        return None

    usuario_id, db_username, email, senha_hash, nome, role = usuario
    st.session_state["usuario_id"] = usuario_id
    st.session_state["username"]   = db_username
    st.session_state["nome"]       = nome
    st.session_state["role"]       = role

    return {"usuario_id": usuario_id, "username": db_username, "nome": nome, "role": role}
