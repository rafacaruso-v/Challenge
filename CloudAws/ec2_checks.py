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

def check_security_groups(session):
    ec2 = session.client("ec2")
    achados = []
    portas_sensiveis = {22: "SSH", 3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL"}

    try:
        sgs = ec2.describe_security_groups()["SecurityGroups"]
    except Exception as e:
        return [{"criticidade": "INFO", "recurso": "EC2", "descricao": f"Erro ao listar security groups: {e}"}]

    for sg in sgs:
        for rule in sg.get("IpPermissions", []):
            from_port = rule.get("FromPort")
            for ip_range in rule.get("IpRanges", []):
                if ip_range.get("CidrIp") == "0.0.0.0/0":
                    servico = portas_sensiveis.get(from_port, f"porta {from_port}")
                    criticidade = "CRITICO" if from_port in portas_sensiveis else "ALTO"
                    achados.append({
                        "criticidade": criticidade,
                        "recurso": f"SG:{sg['GroupId']}",
                        "descricao": f"Security Group '{sg['GroupName']}' libera {servico} para qualquer IP (0.0.0.0/0)."
                    })

    return achados
