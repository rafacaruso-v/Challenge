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

def check_password_policy(session):
    """Verifica a política de senha configurada na conta AWS."""
    iam = session.client("iam")
    achados = []

    try:
        policy = iam.get_account_password_policy()["PasswordPolicy"]

        if policy.get("MinimumPasswordLength", 0) < 14:
            achados.append({
                "criticidade": "MEDIO",
                "recurso": "IAM:PasswordPolicy",
                "descricao": "Política de senha da conta permite senhas com menos de 14 caracteres."
            })

        if not policy.get("RequireSymbols"):
            achados.append({
                "criticidade": "BAIXO",
                "recurso": "IAM:PasswordPolicy",
                "descricao": "Política de senha da conta não exige símbolos."
            })

        if not policy.get("RequireNumbers"):
            achados.append({
                "criticidade": "BAIXO",
                "recurso": "IAM:PasswordPolicy",
                "descricao": "Política de senha da conta não exige números."
            })

        if not policy.get("RequireUppercaseCharacters"):
            achados.append({
                "criticidade": "BAIXO",
                "recurso": "IAM:PasswordPolicy",
                "descricao": "Política de senha da conta não exige letras maiúsculas."
            })

        if not policy.get("MaxPasswordAge"):
            achados.append({
                "criticidade": "BAIXO",
                "recurso": "IAM:PasswordPolicy",
                "descricao": "Política de senha da conta não exige expiração/rotação periódica de senha."
            })

    except iam.exceptions.NoSuchEntityException:
        achados.append({
            "criticidade": "ALTO",
            "recurso": "IAM:PasswordPolicy",
            "descricao": "Nenhuma política de senha customizada configurada na conta (usando padrão da AWS, mais permissivo)."
        })
    except Exception as e:
        achados.append({
            "criticidade": "INFO",
            "recurso": "IAM:PasswordPolicy",
            "descricao": f"Erro ao consultar política de senha: {e}"
        })

    return achados


def check_root_mfa(session):
    """Verifica se a conta root possui MFA habilitado."""
    iam = session.client("iam")
    achados = []

    try:
        summary = iam.get_account_summary()["SummaryMap"]
        if summary.get("AccountMFAEnabled", 0) == 0:
            achados.append({
                "criticidade": "CRITICO",
                "recurso": "IAM:RootAccount",
                "descricao": "A conta root não possui MFA habilitado."
            })
    except Exception as e:
        achados.append({
            "criticidade": "INFO",
            "recurso": "IAM:RootAccount",
            "descricao": f"Erro ao verificar MFA da conta root: {e}"
        })

    return achados
