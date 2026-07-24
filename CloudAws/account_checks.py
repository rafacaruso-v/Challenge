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