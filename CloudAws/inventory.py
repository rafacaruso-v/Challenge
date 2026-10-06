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


def descobrir_inventario(session):
    
    inventario = {
        "buckets_s3": [],
        "usuarios_iam": [],
        "security_groups": [],
        "instancias_ec2": [],
        "erros": [],
    }

    s3 = session.client("s3")
    try:
        buckets = s3.list_buckets()["Buckets"]
        inventario["buckets_s3"] = [b["Name"] for b in buckets]
    except Exception as e:
        inventario["erros"].append(f"S3: {e}")

    iam = session.client("iam")
    try:
        usuarios = iam.list_users()["Users"]
        inventario["usuarios_iam"] = [u["UserName"] for u in usuarios]
    except Exception as e:
        inventario["erros"].append(f"IAM: {e}")

    ec2 = session.client("ec2")
    try:
        sgs = ec2.describe_security_groups()["SecurityGroups"]
        inventario["security_groups"] = [
            {"id": sg["GroupId"], "nome": sg["GroupName"]} for sg in sgs
        ]
    except Exception as e:
        inventario["erros"].append(f"Security Groups: {e}")

    try:
        reservations = ec2.describe_instances()["Reservations"]
        instancias = []
        for r in reservations:
            for i in r["Instances"]:
                tag_nome = next(
                    (t["Value"] for t in i.get("Tags", []) if t["Key"] == "Name"),
                    None
                )
                instancias.append({
                    "id": i["InstanceId"],
                    "nome": tag_nome or i["InstanceId"],
                    "tipo": i.get("InstanceType", "?"),
                    "estado": i.get("State", {}).get("Name", "?"),
                })
        inventario["instancias_ec2"] = instancias
    except Exception as e:
        inventario["erros"].append(f"EC2 Instances: {e}")

    return inventario
