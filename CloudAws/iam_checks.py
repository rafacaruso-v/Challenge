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

        # Policies anexadas diretamente
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

        # MFA
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

        # Idade das access keys
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