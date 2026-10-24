import hashlib
import hmac
import json
import logging
import os

import uvicorn
from dotenv import load_dotenv
from fastapi import FastAPI, Header, HTTPException, Request

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("github-webhook")

WEBHOOK_SECRET = os.environ.get("GITHUB_WEBHOOK_SECRET", "")

app = FastAPI()


def verify_signature(body: bytes, signature: str | None) -> bool:
    if not signature or not signature.startswith("sha256="):
        return False
    expected = "sha256=" + hmac.new(WEBHOOK_SECRET.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


@app.post("/webhook")
async def github_webhook(
    request: Request,
    x_hub_signature_256: str | None = Header(default=None),
    x_github_event: str | None = Header(default=None),
    x_github_delivery: str | None = Header(default=None),
):
    if not WEBHOOK_SECRET:
        logger.error("GITHUB_WEBHOOK_SECRET is not set")
        raise HTTPException(status_code=500, detail="Webhook secret not configured")

    body = await request.body()
    if not verify_signature(body, x_hub_signature_256):
        logger.warning("Rejected webhook delivery %s: invalid signature", x_github_delivery)
        raise HTTPException(status_code=401, detail="Invalid signature")

    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    logger.info(
        "Webhook event=%s delivery=%s payload=%s",
        x_github_event,
        x_github_delivery,
        json.dumps(payload),
    )
    return {"status": "ok"}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
