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