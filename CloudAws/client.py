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

import boto3


def get_session_via_role(role_arn: str, external_id: str, hub_access_key: str, hub_secret_key: str, region: str = "us-east-2"):

    hub_session = boto3.Session(
        aws_access_key_id=hub_access_key,
        aws_secret_access_key=hub_secret_key,
        region_name=region,
    )
    sts = hub_session.client("sts")

    resposta = sts.assume_role(
        RoleArn=role_arn,
        RoleSessionName="aspm-cspm-scan",
        ExternalId=external_id,
    )

    credenciais = resposta["Credentials"]

    return boto3.Session(
        aws_access_key_id=credenciais["AccessKeyId"],
        aws_secret_access_key=credenciais["SecretAccessKey"],
        aws_session_token=credenciais["SessionToken"],
        region_name=region,
    )
