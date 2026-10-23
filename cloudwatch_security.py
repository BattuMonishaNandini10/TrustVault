import json
import logging
import os
import time
from datetime import datetime, timezone

import boto3
from botocore.exceptions import BotoCoreError, ClientError

logger = logging.getLogger(__name__)

LOG_GROUP = "/trustvault/security"
LOG_STREAM = "trustvault-app"
AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")

_logs = boto3.client("logs", region_name=AWS_REGION)


def emit_security_event(username, action, result, details=""):
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "username": str(username or "unknown")[:100],
        "action": str(action)[:50],
        "result": str(result)[:20],
        "details": str(details)[:300],
    }

    try:
        _logs.put_log_events(
            logGroupName=LOG_GROUP,
            logStreamName=LOG_STREAM,
            logEvents=[
                {
                    "timestamp": int(time.time() * 1000),
                    "message": json.dumps(event, separators=(",", ":")),
                }
            ],
        )
    except (BotoCoreError, ClientError, ValueError):
        logger.exception(
            "Could not send TrustVault security event to CloudWatch"
        )