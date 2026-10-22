
import boto3
from botocore.exceptions import ClientError

BUCKET_NAME = "trustvault-3"
REGION = "us-east-1"

try:
    s3 = boto3.client("s3", region_name=REGION)

    response = s3.head_bucket(Bucket=BUCKET_NAME)

    print("SUCCESS: TrustVault connected to Amazon S3!")
    print("Bucket:", BUCKET_NAME)
    print("Region:", REGION)

except ClientError as error:
    print("S3 connection failed.")
    print(error.response["Error"].get("Code", "Unknown error"))
