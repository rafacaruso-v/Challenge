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