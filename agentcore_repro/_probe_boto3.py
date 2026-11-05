import boto3
import botocore
print("boto3", boto3.__version__, "botocore", botocore.__version__)
try:
    import botocore.session
    s = botocore.session.get_session()
    m = s.get_service_model("bedrock-agentcore")
    print("SERVICE bedrock-agentcore OK")
    print("ops:", sorted(m.operation_names))
except Exception as e:
    print("no service:", type(e).__name__, str(e)[:200])