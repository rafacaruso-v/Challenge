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
from CloudAws.client import get_session_via_role
from CloudAws.s3_checks import check_s3
from CloudAws.iam_checks import check_iam
from CloudAws.ec2_checks import check_security_groups
from CloudAws.account_checks import check_password_policy, check_root_mfa
from CloudAws.inventory import descobrir_inventario


def run_cspm_scan(role_arn: str, region: str = "us-east-1"):
    hub_access_key = os.environ.get("AWS_HUB_ACCESS_KEY")
    hub_secret_key = os.environ.get("AWS_HUB_SECRET_KEY")
    external_id = os.environ.get("AWS_EXTERNAL_ID")

    if not hub_access_key or not hub_secret_key:
        raise ValueError("AWS_HUB_ACCESS_KEY / AWS_HUB_SECRET_KEY nao definidas no .env")
    if not external_id:
        raise ValueError("AWS_EXTERNAL_ID nao definida no .env")

    session = get_session_via_role(role_arn, external_id, hub_access_key, hub_secret_key, region)

    achados = []
    achados += check_s3(session)
    achados += check_iam(session)
    achados += check_security_groups(session)
    achados += check_password_policy(session)
    achados += check_root_mfa(session)

    inventario = descobrir_inventario(session)

    return achados, inventario
