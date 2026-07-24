import os
from CloudAws.client import get_session_via_role
from CloudAws.s3_checks import check_s3
from CloudAws.iam_checks import check_iam
from CloudAws.ec2_checks import check_security_groups
from CloudAws.account_checks import check_password_policy, check_root_mfa


def run_cspm_scan(role_arn: str, region: str = "us-east-1"):
    """
    Orquestra todos os checks de CSPM (Cloud Security Posture Management)
    contra a conta AWS do usuario, assumindo a role informada via
    AssumeRole (credenciais temporarias), e retorna uma lista consolidada
    de achados.

    Cada achado segue o formato:
    {
        "criticidade": "CRITICO" | "ALTO" | "MEDIO" | "BAIXO" | "INFO",
        "recurso": str,
        "descricao": str
    }
    """
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

    return achados