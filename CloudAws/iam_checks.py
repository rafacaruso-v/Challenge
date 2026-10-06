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

from datetime import datetime, timezone

def check_iam(session):
    iam = session.client("iam")
    achados = []

    try:
        users = iam.list_users()["Users"]
    except Exception as e:
        return [{"criticidade": "INFO", "recurso": "IAM", "descricao": f"Erro ao listar usuários: {e}"}]

    for u in users:
        username = u["UserName"]

        try:
            attached = iam.list_attached_user_policies(UserName=username)["AttachedPolicies"]
            for p in attached:
                if "AdministratorAccess" in p["PolicyName"]:
                    achados.append({
                        "criticidade": "CRITICO",
                        "recurso": f"IAM:{username}",
                        "descricao": f"Usuário '{username}' possui a política AdministratorAccess anexada diretamente."
                    })
        except Exception:
            pass

        try:
            mfa = iam.list_mfa_devices(UserName=username)["MFADevices"]
            if not mfa:
                achados.append({
                    "criticidade": "ALTO",
                    "recurso": f"IAM:{username}",
                    "descricao": f"Usuário '{username}' não possui MFA habilitado."
                })
        except Exception:
            pass

        try:
            keys = iam.list_access_keys(UserName=username)["AccessKeyMetadata"]
            for k in keys:
                age_days = (datetime.now(timezone.utc) - k["CreateDate"]).days
                if age_days > 90 and k["Status"] == "Active":
                    achados.append({
                        "criticidade": "MEDIO",
                        "recurso": f"IAM:{username}",
                        "descricao": f"Access key de '{username}' ativa há {age_days} dias sem rotação."
                    })
        except Exception:
            pass

    return achados
