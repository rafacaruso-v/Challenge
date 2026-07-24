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