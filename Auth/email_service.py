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
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

GMAIL_USER          = os.environ.get("GMAIL_USER")
GMAIL_APP_PASSWORD  = os.environ.get("GMAIL_APP_PASSWORD")

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 465


def enviar_codigo_mfa(destinatario_email: str, codigo: str) -> bool:

    if not GMAIL_USER or not GMAIL_APP_PASSWORD:
        raise RuntimeError(
            "Variáveis de ambiente GMAIL_USER e GMAIL_APP_PASSWORD não configuradas."
        )

    msg = MIMEMultipart("alternative")
    msg["Subject"] = "ASPM Platform - Código de Verificação"
    msg["From"]    = GMAIL_USER
    msg["To"]      = destinatario_email

    texto = (
        f"Seu código de verificação é: {codigo}\n\n"
        "Este código expira em 10 minutos.\n"
        "Se você não solicitou este login, ignore este e-mail."
    )
    html = f"""
    <div style="font-family:Arial, sans-serif; padding:20px;">
        <h2 style="color:#7c3aed;">ASPM Platform</h2>
        <p>Seu código de verificação é:</p>
        <p style="font-size:32px; font-weight:800; letter-spacing:6px; color:#a855f7;">{codigo}</p>
        <p style="opacity:0.7; font-size:13px;">
            Este código expira em 10 minutos.<br>
            Se você não solicitou este login, ignore este e-mail.
        </p>
    </div>
    """

    msg.attach(MIMEText(texto, "plain"))
    msg.attach(MIMEText(html, "html"))

    try:
        with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT) as servidor:
            servidor.login(GMAIL_USER, GMAIL_APP_PASSWORD)
            servidor.sendmail(GMAIL_USER, destinatario_email, msg.as_string())
        return True
    except Exception as e:
        raise RuntimeError(f"Falha ao enviar e-mail de verificação: {e}")
