"""Private edge revision 2, with upfront two-item shared reservations only.

No SDK client, environment/credential read, listener, provider transport or live
mode exists here. The exported AWS entry point stays closed until a separately
reviewed bootstrap binds this factory. Synthetic results are never live proof.
"""
import base64
from dataclasses import dataclass
import hashlib
import hmac
import json
import math
import re
import secrets
import time
from urllib.parse import urlsplit


MAX_BODY = 16384
SECURITY = {
    "cache-control": "no-store", "x-content-type-options": "nosniff",
    "x-frame-options": "DENY", "referrer-policy": "no-referrer",
    "content-security-policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
}
V2_NOTICE = '<aside class="notice" aria-label="Demo data and storage scope">Synthetic/disconnected edge preparation. POSTs reserve shared request-budget records; these reservations are not execution or provider receipts. No provider API is called, no artist confirmation is stored in DynamoDB, and no candidate or preference data is persisted by this edge.</aside>'
QLOO_OLD_FOOTER = "performs no external API calls."
QLOO_NEW_FOOTER = "makes no external provider API calls. Configured shared storage records only request-budget reservations; those records do not prove execution."


class EdgeError(Exception):
    def __init__(self, code, message, status=400):
        self.code, self.message, self.status = code, message, status


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def digest(value):
    return hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate")
            result[key] = value
        return result

    def reject(_):
        raise ValueError("nonfinite")

    def check(value, depth=0):
        if depth > 12 or isinstance(value, (dict, list)) and len(value) > 128:
            raise ValueError("complex")
        if isinstance(value, (dict, list)):
            for child in value.values() if isinstance(value, dict) else value:
                check(child, depth + 1)

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=reject)
        check(value)
        canonical(value).encode("utf-8")  # Refuse overflow and unpaired Unicode surrogates.
    except (ValueError, UnicodeError, RecursionError):
        raise EdgeError("invalid_json", "Use bounded UTF-8 JSON with unique fields and finite values.") from None
    if not isinstance(value, dict):
        raise EdgeError("invalid_request", "Use a JSON object.")
    return value


@dataclass(frozen=True)
class EdgeConfig:
    app_id: str
    origin: str
    source_revision: str
    expires_at: int
    session_seconds: int = 900

    def __post_init__(self):
        url = urlsplit(self.origin)
        if (self.app_id not in ("qloo", "nebius") or url.scheme != "https"
                or not re.fullmatch(r"[a-z0-9]{16,64}\.lambda-url\.us-east-2\.on\.aws", url.netloc)
                or url.path or url.query or url.fragment):
            raise ValueError("Choose one exact HTTPS us-east-2 Function URL origin.")
        if not isinstance(self.source_revision, str) or not re.fullmatch(r"[a-f0-9]{64}", self.source_revision):
            raise ValueError("Bind an exact source revision.")
        if type(self.expires_at) is not int or self.expires_at <= 0 or type(self.session_seconds) is not int or not 60 <= self.session_seconds <= 900:
            raise ValueError("Choose bounded integer expiry values.")


class QlooDomain:
    actions = frozenset(("/api/resolve", "/api/shortlist"))

    def __init__(self, workflow):
        self.workflow = workflow

    def get(self, path):
        if path == "/api/status":
            return {"provider": dict(self.workflow.PROVIDER)}
        raise EdgeError("not_found", "No such demo route.", 404)

    def post(self, path, packet):
        needed = {"queries"} if path == "/api/resolve" else {"queries", "resolution_id", "selected_ids"}
        if set(packet) != needed:
            raise EdgeError("invalid_request", "Use only the displayed artist-resolution fields.")
        try:
            if path == "/api/resolve":
                return self.workflow.resolve(packet["queries"])
            result = self.workflow.shortlist(**packet)
            result["receipt"]["qualification"] = "Synthetic computation only. Shared budget was reserved separately; that reservation is not an execution or provider receipt. No preference profile was saved or provider API called."
            return result
        except self.workflow.WorkflowError as exc:
            raise EdgeError(exc.code, exc.message, exc.status) from None


class NebiusDomain:
    actions = frozenset(("/api/validate", "/api/propose"))

    def __init__(self, triage, proposal_service):
        self.triage, self.proposals = triage, proposal_service

    def get(self, path):
        if path == "/api/provider":
            return {"provider": {"name": "Nebius Token Factory", "status": "disconnected", "execution_verified": False}, "mode": "disconnected", "proposal_available": False}
        if path == "/api/cases":
            return {"provider": dict(self.triage.PROVIDER), "cases": [{"id": c["id"], "title": c["title"]} for c in self.triage.CASES]}
        if path.startswith("/api/cases/"):
            try:
                case = self.triage.case_by_id(path.removeprefix("/api/cases/"))
                return {"case": case, "samples": {kind: self.triage.sample(case, kind) for kind in ("supported", "invented", "stale", "abstain")}}
            except self.triage.InputError:
                raise EdgeError("not_found", "Choose a listed authored case.", 404) from None
        raise EdgeError("not_found", "No such demo route.", 404)

    def post(self, path, packet):
        try:
            if path == "/api/propose":
                # This path cannot accept a configured ProposalService or key.
                return self.proposals.disconnected_response(packet)
            if set(packet) != {"case_id", "candidate"} or not isinstance(packet["candidate"], str):
                raise EdgeError("invalid_request", "Send only a case ID and candidate JSON text.")
            candidate = packet["candidate"].encode("utf-8")
            if len(candidate) > 8192:
                raise EdgeError("body_limit", "Candidate JSON exceeds the authored-case limit.", 413)
            return {"report": self.triage.validate(packet["case_id"], strict_json(candidate))}
        except UnicodeError:
            raise EdgeError("invalid_source", "Use valid UTF-8 candidate JSON.") from None
        except self.triage.InputError:
            raise EdgeError("invalid_source", "Invalid or stale authored-case request. Reload the case and review its source.") from None


class DemoHandler:
    """One app per instance. Nonces protect anonymous demo requests, not approval.

    `quota` must implement the separately reviewed durable v2 reserve contract;
    an absent object fails every POST closed. A reservation is not an execution
    receipt. Current domains are synthetic/disconnected and make no other writes.
    """
    def __init__(self, config, *, index_html, domain, quota=None, signing_key, clock=time.time, random_bytes=secrets.token_bytes):
        if not isinstance(config, EdgeConfig) or not isinstance(index_html, bytes) or len(index_html) > 131072:
            raise ValueError("Choose one reviewed bounded UI and edge config.")
        expected = QlooDomain if config.app_id == "qloo" else NebiusDomain
        if not isinstance(domain, expected) or not isinstance(signing_key, bytes) or len(signing_key) < 32:
            raise ValueError("Bind the exact disconnected domain and an explicit private signing key.")
        if quota is not None and not callable(getattr(quota, "reserve", None)):
            raise ValueError("Bind the durable v2 reserve contract, or leave POSTs disabled.")
        try:
            self.html = index_html.decode("utf-8")
        except UnicodeError:
            raise ValueError("The UI must be UTF-8.") from None
        if self.html.count("<head>") != 1 or self.html.count("<body>") != 1:
            raise ValueError("The reviewed UI must contain one head and body element.")
        if config.app_id == "qloo" and self.html.count(QLOO_OLD_FOOTER) != 1:
            raise ValueError("The reviewed synthetic Qloo disclosure changed; inspect it before binding.")
        self.config, self.domain, self.quota = config, domain, quota
        self.key, self.clock, self.random_bytes = signing_key, clock, random_bytes
        self.host = urlsplit(config.origin).netloc
        self.cookie_name = "__Host-hackathon-demo-" + config.app_id

    def _sign(self, value):
        return hmac.new(self.key, value.encode("utf-8"), hashlib.sha256).hexdigest()

    def _nonce(self, session, path):
        return self._sign("nonce:" + session + ":" + self.config.source_revision + ":" + path)

    def _session(self, now):
        random = self.random_bytes(24)
        if not isinstance(random, bytes) or len(random) != 24:
            raise EdgeError("session_unavailable", "Demo session unavailable.", 503)
        expiry = min(now + self.config.session_seconds, self.config.expires_at)
        text = canonical({"a": self.config.app_id, "e": expiry, "i": random.hex(), "r": self.config.source_revision})
        encoded = base64.urlsafe_b64encode(text.encode()).decode().rstrip("=")
        return encoded + "." + self._sign("session:" + encoded), expiry

    def _check_session(self, cookies, now):
        if not isinstance(cookies, list) or len(cookies) > 20 or any(not isinstance(v, str) or len(v) > 4096 for v in cookies):
            raise EdgeError("session_required", "Reload this demo page to establish a session.", 403)
        found = [part.strip().split("=", 1)[1] for value in cookies for part in value.split(";") if part.strip().startswith(self.cookie_name + "=")]
        if len(found) != 1:
            raise EdgeError("session_required", "Reload this demo page to establish a session.", 403)
        token = found[0]
        try:
            encoded, signature = token.split(".")
            if not hmac.compare_digest(self._sign("session:" + encoded), signature):
                raise ValueError()
            data = strict_json(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
            if (set(data) != {"a", "e", "i", "r"} or data["a"] != self.config.app_id
                    or data["r"] != self.config.source_revision or type(data["e"]) is not int
                    or not now < data["e"] <= min(now + self.config.session_seconds, self.config.expires_at)
                    or not isinstance(data["i"], str) or not re.fullmatch("[0-9a-f]{48}", data["i"])):
                raise ValueError()
        except (ValueError, UnicodeError, EdgeError):
            raise EdgeError("session_expired", "Session expired or source changed. Reload the demo page.", 403) from None
        return token

    def _response(self, status, value, *, html=False, cookie=None):
        headers = {**SECURITY, "content-type": "text/html; charset=utf-8" if html else "application/json; charset=utf-8", "x-demo-source-revision": self.config.source_revision}
        if not html and self.config.app_id == "nebius" and isinstance(value, dict) and isinstance(value.get("error"), dict):
            value = {"error": value["error"]["message"], "error_code": value["error"]["code"]}
        payload = value if html else canonical(value)
        payload.encode("utf-8")
        response = {"statusCode": status, "headers": headers, "body": payload, "isBase64Encoded": False}
        if cookie is not None:
            response["cookies"] = [cookie]
        return response

    def _index(self, now):
        session, expiry = self._session(now)
        boot = {"revision": self.config.source_revision, "nonces": {path: self._nonce(session, path) for path in sorted(self.domain.actions)}}
        # The existing UI keeps its payload/response schema. This first script
        # adds only origin-bound edge headers; no key or cookie is exposed to JS.
        script = "<script>\n(()=>{const edge=" + canonical(boot) + ";const original=window.fetch.bind(window);window.fetch=(input,options={})=>{const u=new URL(typeof input==='string'?input:input.url,location.href);if(u.origin===location.origin&&String(options.method||'GET').toUpperCase()==='POST'&&Object.hasOwn(edge.nonces,u.pathname)){const headers=new Headers(options.headers||{});headers.set('X-Demo-Nonce',edge.nonces[u.pathname]);headers.set('X-Demo-Revision',edge.revision);headers.set('X-Demo-Request',crypto.randomUUID().replaceAll('-',''));return original(input,{...options,headers,credentials:'same-origin'});}return original(input,options);};})();\n</script>"
        html = self.html.replace("<head>", "<head>" + script, 1).replace("<body>", "<body>" + V2_NOTICE, 1)
        if self.config.app_id == "qloo":
            html = html.replace(QLOO_OLD_FOOTER, QLOO_NEW_FOOTER, 1)
        cookie = f"{self.cookie_name}={session}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age={expiry-now}"
        return self._response(200, html, html=True, cookie=cookie)

    def __call__(self, event, context=None):
        try:
            clock = self.clock()
            if type(clock) not in (int, float) or not math.isfinite(clock) or clock < 0:
                raise EdgeError("clock_unavailable", "Trusted demo time is unavailable.", 503)
            now = int(clock)
            if now >= self.config.expires_at:
                raise EdgeError("demo_expired", "The temporary demo has expired. No provider call is available.", 410)
            if not isinstance(event, dict) or event.get("version") != "2.0":
                raise EdgeError("event_rejected", "Use the configured Function URL v2 endpoint.")
            raw_headers = event.get("headers")
            if not isinstance(raw_headers, dict) or len(raw_headers) > 80:
                raise EdgeError("headers_rejected", "Invalid request headers.")
            headers = {}
            for key, value in raw_headers.items():
                if not isinstance(key, str) or not isinstance(value, str) or len(key) > 100 or len(value) > 4096 or key.lower() in headers or any(c in value for c in "\r\n"):
                    raise EdgeError("headers_rejected", "Invalid request headers.")
                headers[key.lower()] = value
            if sum(len(key) + len(value) for key, value in headers.items()) > 16384:
                raise EdgeError("headers_rejected", "Request headers exceed the demo limit.", 431)
            request_context = event.get("requestContext", {})
            if not isinstance(request_context, dict) or not isinstance(request_context.get("http"), dict):
                raise EdgeError("event_rejected", "Use the configured Function URL v2 envelope.")
            http = request_context["http"]
            if headers.get("host") != self.host or request_context.get("domainName") != self.host or headers.get("x-forwarded-proto") != "https":
                raise EdgeError("host_rejected", "Use the exact configured HTTPS demo endpoint.", 403)
            method, path = http.get("method"), event.get("rawPath")
            if not isinstance(path, str) or len(path) > 160 or "%" in path or event.get("rawQueryString", ""):
                raise EdgeError("route_rejected", "Use a displayed demo route.", 404)
            if method == "GET":
                if event.get("body") not in (None, ""):
                    raise EdgeError("body_rejected", "GET requests accept no body.")
                return self._index(now) if path == "/" else self._response(200, self.domain.get(path))
            if method != "POST" or path not in self.domain.actions:
                raise EdgeError("not_found", "No such demo action.", 404)
            if headers.get("origin") != self.config.origin or headers.get("sec-fetch-site", "same-origin") != "same-origin":
                raise EdgeError("origin_rejected", "Use this demo's own page.", 403)
            if headers.get("content-type", "").split(";")[0].strip().lower() != "application/json":
                raise EdgeError("json_required", "Use a JSON request.", 415)
            if "transfer-encoding" in headers or "cookie" in headers:
                raise EdgeError("headers_rejected", "Use the Function URL cookie envelope.")
            session = self._check_session(event.get("cookies", []), now)
            if headers.get("x-demo-revision") != self.config.source_revision:
                raise EdgeError("source_changed", "Demo source changed. Reload the page.", 409)
            if not hmac.compare_digest(headers.get("x-demo-nonce", ""), self._nonce(session, path)):
                raise EdgeError("nonce_rejected", "Action nonce is invalid. Reload this demo page.", 403)
            request_id = headers.get("x-demo-request", "")
            if not re.fullmatch(r"[A-Za-z0-9_-]{16,80}", request_id):
                raise EdgeError("request_id_required", "Use one bounded unique request ID.")
            raw = event.get("body")
            if not isinstance(raw, str) or len(raw) > MAX_BODY * 2 or type(event.get("isBase64Encoded", False)) is not bool:
                raise EdgeError("body_limit", "Request body exceeds the demo limit.", 413)
            try:
                body = base64.b64decode(raw, validate=True) if event.get("isBase64Encoded", False) else raw.encode("utf-8")
            except (ValueError, UnicodeError):
                raise EdgeError("invalid_body", "Use a valid UTF-8 JSON body.") from None
            if len(body) > MAX_BODY:
                raise EdgeError("body_limit", "Request body exceeds the demo limit.", 413)
            if "content-length" in headers and headers["content-length"] != str(len(body)):
                raise EdgeError("body_length", "Request length does not match its decoded body.")
            packet = strict_json(body)
            if self.quota is None:
                raise EdgeError("quota_unconfigured", "Shared request allowance is not configured. No action started.", 503)
            fingerprint = digest({"app": self.config.app_id, "path": path, "revision": self.config.source_revision, "session": hashlib.sha256(session.encode()).hexdigest(), "body": hashlib.sha256(body).hexdigest()})
            # Upfront accounting and replay barrier only. There is no finish
            # write, normalized-confirmation store or provider call in this edge.
            permit = self.quota.reserve(request_id, fingerprint, use_provider=False)
            if (getattr(permit, "app_id", None) != self.config.app_id
                    or getattr(permit, "fingerprint", None) != fingerprint
                    or getattr(permit, "raw_reserved", None) != 0):
                raise EdgeError("reservation_rejected", "Synthetic demo needs a matching zero-provider reservation.", 503)
            result = self.domain.post(path, packet)
            return self._response(200, result)
        except EdgeError as error:
            return self._response(error.status, {"error": {"code": error.code, "message": error.message}})
        except Exception as error:
            # QuotaError has sanitized contract fields. Never reflect arbitrary
            # exception text, event bodies, credentials or infrastructure IDs.
            if error.__class__.__name__ == "QuotaError" and isinstance(getattr(error, "code", None), str):
                code = error.code if re.fullmatch(r"[a-z_]{1,60}", error.code) else "quota_unavailable"
                status = error.status if type(getattr(error, "status", None)) is int and 400 <= error.status <= 599 else 503
                if code == "quota_paced":
                    message = "No action started. Wait at least two seconds, then click again explicitly. Automatic retries are disabled."
                elif code in {"replay_reserved", "quota_uncertain", "reservation_timing_unknown"}:
                    message = "This request has a prior or uncertain reservation. Inspect the original outcome; its execution is not established. Do not automatically retry."
                else:
                    message = "Shared allowance or prior reservation needs review. No new provider request is available. Do not automatically retry."
                return self._response(status, {"error": {"code": code, "message": message}})
            return self._response(503, {"error": {"code": "demo_unavailable", "message": "Demo request unavailable. A prior reservation may be uncertain; do not retry automatically."}})


def handler(event, context):
    """Deliberately closed bootstrap. No implicit credentials, config or client."""
    return {"statusCode": 503, "headers": {**SECURITY, "content-type": "application/json; charset=utf-8"},
            "body": canonical({"error": {"code": "binding_unconfigured", "message": "Private Lambda binding is not configured. Live providers are disconnected."}}), "isBase64Encoded": False}
