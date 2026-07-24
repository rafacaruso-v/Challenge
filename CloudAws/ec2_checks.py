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