
import boto3

BUCKET_NAME = "trustvault-3"
REGION = "us-east-1"

s3 = boto3.client("s3", region_name=REGION)
s3.head_bucket(Bucket=BUCKET_NAME)

print("SUCCESS: TrustVault connected to Amazon S3!")
print("Bucket:", BUCKET_NAME)
print("Region:", REGION)
