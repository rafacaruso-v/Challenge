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

def check_s3(session):
    s3 = session.client("s3")
    achados = []

    try:
        buckets = s3.list_buckets()["Buckets"]
    except Exception as e:
        return [{"criticidade": "INFO", "recurso": "S3", "descricao": f"Erro ao listar buckets: {e}"}]

    for b in buckets:
        name = b["Name"]

        try:
            policy = s3.get_bucket_policy(Bucket=name)
            import json
            policy_doc = json.loads(policy["Policy"])
            for stmt in policy_doc.get("Statement", []):
                principal = stmt.get("Principal")
                if principal == "*" or (isinstance(principal, dict) and principal.get("AWS") == "*"):
                    if stmt.get("Effect") == "Allow":
                        achados.append({
                            "criticidade": "CRITICO",
                            "recurso": f"S3:{name}",
                            "descricao": f"Bucket '{name}' possui bucket policy permitindo acesso público (Principal: *)."
                        })
        except s3.exceptions.from_code("NoSuchBucketPolicy"):
            pass
        except Exception:
            pass

        try:
            acl = s3.get_bucket_acl(Bucket=name)
            for grant in acl["Grants"]:
                uri = grant.get("Grantee", {}).get("URI", "")
                if uri.endswith("AllUsers") or uri.endswith("AuthenticatedUsers"):
                    achados.append({
                        "criticidade": "CRITICO",
                        "recurso": f"S3:{name}",
                        "descricao": f"Bucket '{name}' permite acesso público via ACL."
                    })
        except Exception:
            pass

        try:
            s3.get_bucket_encryption(Bucket=name)
        except Exception:
            achados.append({
                "criticidade": "MEDIO",
                "recurso": f"S3:{name}",
                "descricao": f"Bucket '{name}' sem criptografia em repouso configurada."
            })

        try:
            ver = s3.get_bucket_versioning(Bucket=name)
            if ver.get("Status") != "Enabled":
                achados.append({
                    "criticidade": "BAIXO",
                    "recurso": f"S3:{name}",
                    "descricao": f"Bucket '{name}' sem versionamento habilitado."
                })
        except Exception:
            pass

    return achados
