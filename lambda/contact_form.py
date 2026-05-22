"""MiLu contact form handler.

Receives POSTs from https://milu.company/contact/ and sends an email via SES.
The form posts either JSON or url-encoded form data. The function URL is
exposed publicly (AuthType=NONE) and protected by:
  - CORS, restricting browser POSTs to the milu.company origins
  - A honeypot field (`_gotcha`)
  - Field validation (length, format, required)
  - SES sandbox (sender domain + recipient address are both verified)
"""

import base64
import json
import logging
import os
import re
from urllib.parse import parse_qs

import boto3
from botocore.exceptions import ClientError

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger()
logger.setLevel(logging.INFO)

REGION = os.environ.get("SES_REGION", "eu-central-1")
SENDER = os.environ.get("SENDER", "contact@milu.company")
RECIPIENT = os.environ.get("RECIPIENT", "mike@milu.company")

ALLOWED_ORIGINS = {
    "https://milu.company",
    "https://www.milu.company",
    # local dev preview
    "http://localhost:8772",
    "http://127.0.0.1:8772",
}

MAX_NAME_LEN = 100
MAX_EMAIL_LEN = 254
MAX_SUBJECT_LEN = 200
MAX_MESSAGE_LEN = 5000
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

ses = boto3.client("ses", region_name=REGION)


def _cors_headers(origin: str) -> dict:
    headers = {
        "Access-Control-Allow-Methods": "POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type",
        "Access-Control-Max-Age": "3600",
        "Vary": "Origin",
    }
    if origin in ALLOWED_ORIGINS:
        headers["Access-Control-Allow-Origin"] = origin
    return headers


def _response(status: int, body: dict, origin: str) -> dict:
    return {
        "statusCode": status,
        "headers": {**_cors_headers(origin), "Content-Type": "application/json"},
        "body": json.dumps(body),
    }


def _parse_body(event: dict) -> dict:
    raw = event.get("body") or ""
    if event.get("isBase64Encoded"):
        raw = base64.b64decode(raw).decode("utf-8", errors="replace")
    if not raw:
        return {}
    content_type = ""
    for k, v in (event.get("headers") or {}).items():
        if k.lower() == "content-type":
            content_type = (v or "").lower()
            break
    if "application/json" in content_type:
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {}
    # default to form-encoded
    parsed = parse_qs(raw, keep_blank_values=True)
    return {k: v[0] if v else "" for k, v in parsed.items()}


def _validate(fields: dict) -> tuple[bool, str]:
    if fields.get("_gotcha"):
        # honeypot was filled, silently succeed without sending
        return False, "ok"
    name = (fields.get("name") or "").strip()
    email = (fields.get("email") or "").strip()
    subject = (fields.get("subject") or "").strip()
    message = (fields.get("message") or "").strip()
    if not name or len(name) > MAX_NAME_LEN:
        return False, "Please enter a name (up to 100 characters)."
    if not email or len(email) > MAX_EMAIL_LEN or not EMAIL_RE.match(email):
        return False, "Please enter a valid email address."
    if len(subject) > MAX_SUBJECT_LEN:
        return False, "Subject is too long (200 character maximum)."
    if not message or len(message) > MAX_MESSAGE_LEN:
        return False, "Please enter a message (up to 5,000 characters)."
    return True, ""


def lambda_handler(event, context):  # noqa: D401  AWS-required name
    method = (
        event.get("requestContext", {})
        .get("http", {})
        .get("method")
        or event.get("httpMethod")
        or "GET"
    ).upper()
    origin = ""
    for k, v in (event.get("headers") or {}).items():
        if k.lower() == "origin":
            origin = v or ""
            break

    # CORS preflight
    if method == "OPTIONS":
        return {"statusCode": 204, "headers": _cors_headers(origin), "body": ""}

    if method != "POST":
        return _response(405, {"error": "Method not allowed"}, origin)

    if origin and origin not in ALLOWED_ORIGINS:
        # Browser would have already blocked this, but be defensive.
        return _response(403, {"error": "Origin not allowed"}, origin)

    fields = _parse_body(event)
    ok, msg = _validate(fields)
    if not ok:
        if msg == "ok":
            # honeypot — pretend it worked
            return _response(200, {"ok": True}, origin)
        return _response(400, {"error": msg}, origin)

    name = fields["name"].strip()
    sender_email = fields["email"].strip()
    subject = (fields.get("subject") or "").strip() or "MiLu contact form"
    message = fields["message"].strip()

    body_text = (
        f"From: {name} <{sender_email}>\n"
        f"Subject: {subject}\n"
        f"------\n\n"
        f"{message}\n"
    )

    try:
        ses.send_email(
            Source=SENDER,
            Destination={"ToAddresses": [RECIPIENT]},
            Message={
                "Subject": {"Data": f"[MiLu] {subject}", "Charset": "UTF-8"},
                "Body": {"Text": {"Data": body_text, "Charset": "UTF-8"}},
            },
            ReplyToAddresses=[sender_email],
        )
    except ClientError as exc:
        logger.exception("SES send_email failed")
        return _response(
            502,
            {"error": "Sorry, something broke on my end. Please try again later."},
            origin,
        )

    return _response(200, {"ok": True}, origin)
