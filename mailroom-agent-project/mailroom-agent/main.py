import base64
import hashlib
import json
import os
import sqlite3
import time
from typing import Any, Dict, List, Optional
import nacl.signing
from fastapi import FastAPI, HTTPException, Request, Response

DB_PATH = os.environ.get("DB_PATH", "mailroom.db")

def canonical_json_bytes(obj: Any) -> bytes:
    """Recursively key-sorted compact JSON bytes (UTF-8)."""
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().lower()


def compute_input_digest(dossiers: List[Dict[str, Any]]) -> str:
    return sha256_hex(canonical_json_bytes(dossiers))


def compute_proposal_digest(proposal: Dict[str, Any]) -> str:
    """
    Normalized proposal digest:
    Keeps only dossierId, callId, action, target (null if absent), payload, evidence.
    Evidence list must be sorted.
    """
    normalized = {
        "dossierId": proposal["dossierId"],
        "callId": proposal["callId"],
        "action": proposal["action"],
        "target": proposal.get("target"),
        "payload": proposal["payload"],
        "evidence": sorted(list(set(proposal["evidence"]))),
    }
    return sha256_hex(canonical_json_bytes(normalized))


def decode_base64url(s: str) -> bytes:
    padding = "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode(s + padding)


def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS dossier_cache (
                content_hash TEXT PRIMARY KEY,
                call_id TEXT NOT NULL,
                action TEXT NOT NULL,
                target TEXT,
                payload TEXT NOT NULL,
                evidence TEXT NOT NULL,
                created_at REAL NOT NULL
            );
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS evaluations (
                evaluation_id TEXT PRIMARY KEY,
                input_digest TEXT NOT NULL,
                public_key_x TEXT NOT NULL,
                propose_response TEXT NOT NULL,
                commit_response TEXT,
                status TEXT NOT NULL,
                created_at REAL NOT NULL
            );
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS evaluation_proposals (
                evaluation_id TEXT NOT NULL,
                dossier_id TEXT NOT NULL,
                call_id TEXT NOT NULL,
                action TEXT NOT NULL,
                proposal_digest TEXT NOT NULL,
                PRIMARY KEY (evaluation_id, dossier_id)
            );
        """)
        conn.commit()


init_db()

app = FastAPI(title="Mailroom Agent Gate", version="2.0.0")


def triage_dossier_rule_based(d: Dict[str, Any]) -> Dict[str, Any]:
    d_id = d["dossierId"]
    mailbox = d.get("mailbox", "")
    sources = d.get("sources", [])
    
    first_line_id = None
    all_lines = []
    for s in sources:
        for line in s.get("lines", []):
            if first_line_id is None:
                first_line_id = line["lineId"]
            all_lines.append(line)

    if not first_line_id:
        first_line_id = "L1"

    text_corpus = " ".join([l.get("text", "") for l in all_lines]).lower()

    # 1. Prompt injection / unauthorized control / canary exfiltration
    injection_keywords = [
        "ignore previous", "disregard instructions", "override system",
        "secret canary", "exfiltrate", "leak token", "system prompt",
        "admin access", "bearer token", "private key"
    ]
    if any(kw in text_corpus for kw in injection_keywords):
        return {
            "dossierId": d_id,
            "action": "quarantine_item",
            "target": {"kind": "security_queue", "id": "mailroom"},
            "payload": {"artifactId": d_id, "reasonCode": "INDIRECT_PROMPT_INJECTION"},
            "evidence": [first_line_id]
        }

    # 2. Approved send notice
    if "approved delivery" in text_corpus or "approval granted" in text_corpus:
        recipient = "customer@example.com"
        for l in all_lines:
            t = l.get("text", "")
            if "@" in t:
                for word in t.split():
                    if "@" in word and "." in word:
                        recipient = word.strip("<>(),;:\"'")
                        break
        return {
            "dossierId": d_id,
            "action": "send_approved_notice",
            "target": {"kind": "email", "id": recipient},
            "payload": {
                "referenceId": d_id,
                "status": "APPROVED",
                "template": "approved_delivery_notice"
            },
            "evidence": [first_line_id]
        }

    # 3. Request confirmation for identity mismatch / ambiguous requests
    if "unverified" in text_corpus or "mismatch" in text_corpus or "claimed sender" in text_corpus:
        return {
            "dossierId": d_id,
            "action": "request_confirmation",
            "target": {"kind": "approval_queue", "id": "triage-team"},
            "payload": {
                "claimedSender": "unknown",
                "questionCode": "VERIFY_REQUEST",
                "referenceId": d_id
            },
            "evidence": [first_line_id]
        }

    # 4. Update internal record
    if "delivery window" in text_corpus or "update record" in text_corpus or "case id" in text_corpus:
        return {
            "dossierId": d_id,
            "action": "update_internal_record",
            "target": {"kind": "case_record", "id": f"case-{d_id}"},
            "payload": {
                "field": "delivery_window",
                "sourceEventId": d_id,
                "value": "standard"
            },
            "evidence": [first_line_id]
        }

    # 5. Create draft
    if "draft" in text_corpus or "order status" in text_corpus:
        return {
            "dossierId": d_id,
            "action": "create_draft",
            "target": {"kind": "draft_queue", "id": f"mailbox:{mailbox or 'general'}"},
            "payload": {
                "recipient": "customer@example.com",
                "referenceId": d_id,
                "status": "PENDING",
                "template": "order_status"
            },
            "evidence": [first_line_id]
        }

    # 6. Default to no_action
    return {
        "dossierId": d_id,
        "action": "no_action",
        "target": None,
        "payload": {
            "reasonCode": "INFORMATIONAL",
            "referenceId": d_id
        },
        "evidence": [first_line_id]
    }


def resolve_proposals(dossiers: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    proposals = []
    with sqlite3.connect(DB_PATH) as conn:
        for d in dossiers:
            d_id = d["dossierId"]
            c_hash = sha256_hex(canonical_json_bytes(d))

            cur = conn.execute(
                "SELECT call_id, action, target, payload, evidence FROM dossier_cache WHERE content_hash = ?",
                (c_hash,),
            )
            row = cur.fetchone()
            if row:
                call_id, action, target, payload, evidence = row
                proposals.append({
                    "dossierId": d_id,
                    "callId": call_id,
                    "action": action,
                    "target": json.loads(target) if target else None,
                    "payload": json.loads(payload),
                    "evidence": json.loads(evidence),
                })
            else:
                decision = triage_dossier_rule_based(d)
                call_id = f"call_{c_hash[:16]}"
                action = decision["action"]
                target = decision.get("target")
                payload = decision["payload"]
                evidence = sorted(list(set(decision.get("evidence", []))))

                conn.execute(
                    """
                    INSERT OR REPLACE INTO dossier_cache (content_hash, call_id, action, target, payload, evidence, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        c_hash,
                        call_id,
                        action,
                        json.dumps(target) if target else None,
                        json.dumps(payload),
                        json.dumps(evidence),
                        time.time(),
                    ),
                )
                proposals.append({
                    "dossierId": d_id,
                    "callId": call_id,
                    "action": action,
                    "target": target,
                    "payload": payload,
                    "evidence": evidence,
                })
        conn.commit()

    order = {d["dossierId"]: i for i, d in enumerate(dossiers)}
    proposals.sort(key=lambda p: order[p["dossierId"]])
    return proposals


@app.post("/")
@app.post("/v1/mailroom/actions")
async def handle_request(req: Request):
    try:
        body = await req.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="Root must be an object")

    profile = body.get("profile")
    if profile != "ga5-mailroom-action-gate/v2":
        raise HTTPException(status_code=400, detail="Unsupported profile")

    operation = body.get("operation")
    if operation == "propose":
        return handle_propose(body)
    elif operation == "commit":
        return handle_commit(body)
    else:
        raise HTTPException(status_code=400, detail=f"Unknown operation: {operation}")


def handle_propose(body: Dict[str, Any]) -> Response:
    eval_id = body.get("evaluationId")
    verifier = body.get("receiptVerifier", {})
    dossiers = body.get("dossiers")

    if not eval_id or not isinstance(dossiers, list):
        raise HTTPException(status_code=400, detail="Missing required propose fields")

    seen_ids = set()
    for d in dossiers:
        d_id = d.get("dossierId")
        if not d_id or d_id in seen_ids:
            raise HTTPException(status_code=400, detail="Duplicate or empty dossierId")
        seen_ids.add(d_id)

    input_digest = compute_input_digest(dossiers)
    public_key_x = verifier.get("publicKeyJwk", {}).get("x", "")

    # Replay and conflict checks
    with sqlite3.connect(DB_PATH) as conn:
        cur = conn.execute(
            "SELECT input_digest, propose_response FROM evaluations WHERE evaluation_id = ?",
            (eval_id,),
        )
        row = cur.fetchone()
        if row:
            stored_digest, stored_response = row
            if stored_digest != input_digest:
                raise HTTPException(status_code=409, detail="Evaluation ID conflict with different content")
            return Response(content=stored_response, media_type="application/json")

    proposals = resolve_proposals(dossiers)

    resp_data = {
        "profile": "ga5-mailroom-action-gate/v2",
        "evaluationId": eval_id,
        "status": "awaiting_receipts",
        "inputDigest": input_digest,
        "proposals": proposals,
    }
    resp_bytes = canonical_json_bytes(resp_data)

    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            INSERT INTO evaluations (evaluation_id, input_digest, public_key_x, propose_response, status, created_at)
            VALUES (?, ?, ?, ?, 'awaiting_receipts', ?)
            """,
            (eval_id, input_digest, public_key_x, resp_bytes.decode("utf-8"), time.time()),
        )
        for p in proposals:
            p_digest = compute_proposal_digest(p)
            conn.execute(
                """
                INSERT INTO evaluation_proposals (evaluation_id, dossier_id, call_id, action, proposal_digest)
                VALUES (?, ?, ?, ?, ?)
                """,
                (eval_id, p["dossierId"], p["callId"], p["action"], p_digest),
            )
        conn.commit()

    return Response(content=resp_bytes, media_type="application/json")


def handle_commit(body: Dict[str, Any]) -> Response:
    eval_id = body.get("evaluationId")
    input_digest = body.get("inputDigest")
    receipts = body.get("receipts")

    if not eval_id or not input_digest or not isinstance(receipts, list):
        raise HTTPException(status_code=400, detail="Malformed commit envelope")

    with sqlite3.connect(DB_PATH) as conn:
        cur = conn.execute(
            "SELECT input_digest, public_key_x, commit_response FROM evaluations WHERE evaluation_id = ?",
            (eval_id,),
        )
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=400, detail="Unknown evaluationId")

        stored_digest, public_key_x, commit_response = row

        if stored_digest != input_digest:
            raise HTTPException(status_code=409, detail="inputDigest does not match evaluation")

        if commit_response:
            return Response(content=commit_response, media_type="application/json")

        cur = conn.execute(
            "SELECT dossier_id, call_id, action, proposal_digest FROM evaluation_proposals WHERE evaluation_id = ?",
            (eval_id,),
        )
        expected_proposals = {r[0]: {"callId": r[1], "action": r[2], "digest": r[3]} for r in cur.fetchall()}

    try:
        raw_pubkey = decode_base64url(public_key_x)
        verify_key = nacl.signing.VerifyKey(raw_pubkey)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid verifier public key")

    outcomes = []
    seen_call_ids = set()

    for r in receipts:
        d_id = r.get("dossierId")
        call_id = r.get("callId")
        action = r.get("action")
        accepted = r.get("accepted")
        p_digest = r.get("proposalDigest")
        receipt_id = r.get("receiptId")
        sig_b64 = r.get("receiptSignature")

        if d_id not in expected_proposals:
            raise HTTPException(status_code=400, detail=f"Dossier {d_id} not in evaluation")

        exp = expected_proposals[d_id]
        if exp["callId"] != call_id or exp["action"] != action or exp["digest"] != p_digest:
            raise HTTPException(status_code=400, detail="Receipt mismatch")

        if call_id in seen_call_ids:
            raise HTTPException(status_code=400, detail="Duplicate callId receipt")
        seen_call_ids.add(call_id)

        inner_receipt = {
            "accepted": accepted,
            "action": action,
            "callId": call_id,
            "dossierId": d_id,
            "proposalDigest": p_digest,
            "receiptId": receipt_id,
        }
        verification_envelope = {
            "evaluationId": eval_id,
            "inputDigest": input_digest,
            "profile": "ga5-mailroom-action-gate/v2",
            "receipt": inner_receipt,
        }
        msg_bytes = canonical_json_bytes(verification_envelope)

        try:
            sig_bytes = base64.b64decode(sig_b64)
            verify_key.verify(msg_bytes, sig_bytes)
        except Exception:
            raise HTTPException(status_code=400, detail=f"Invalid receiptSignature for {d_id}")

        outcomes.append({
            "dossierId": d_id,
            "callId": call_id,
            "action": action,
            "proposalDigest": p_digest,
            "receiptId": receipt_id,
            "status": "executed" if accepted is True else "rejected",
        })

    resp_data = {
        "profile": "ga5-mailroom-action-gate/v2",
        "evaluationId": eval_id,
        "status": "completed",
        "inputDigest": input_digest,
        "outcomes": outcomes,
    }
    resp_bytes = canonical_json_bytes(resp_data)

    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "UPDATE evaluations SET commit_response = ?, status = 'completed' WHERE evaluation_id = ?",
            (resp_bytes.decode("utf-8"), eval_id),
        )
        conn.commit()

    return Response(content=resp_bytes, media_type="application/json")
