"""Explicit private Nebius composition; import performs no SDK or credential work.

The exported handler is always closed. Only an explicitly constructed factory
can compose reviewed stores, a key supplied by its caller and an async transport.
No default environment, key lookup, HTTP client or persistence path exists.
"""
import asyncio
from contextvars import ContextVar
import base64
import hashlib
import hmac
import inspect
import math
import re
import time

from edge_base import (DemoHandler, EdgeConfig, EdgeError, NebiusDomain,
                       SECURITY, MAX_BODY, V2_NOTICE, canonical, digest, strict_json)
from global_quota_v2 import RequestPermit
from nebius_adapter import ENDPOINT, MAX_RESPONSE_BYTES, TIMEOUT_SECONDS
from proposal_service import ProposalService, validate_packet
from triage import InputError

_INVOCATION = ContextVar("nebius_cloud_invocation", default=None)


def _remaining_invocation_seconds():
    context = _INVOCATION.get()
    method = getattr(context, "get_remaining_time_in_millis", None)
    if not callable(method):
        raise EdgeError("invocation_deadline_required", "A trusted cloud invocation deadline is required.", 503)
    try:
        value = method()
    except Exception:
        raise EdgeError("invocation_deadline_required", "Trusted remaining time is unavailable.", 503) from None
    if type(value) not in (int, float) or not math.isfinite(value) or value <= 0:
        raise EdgeError("invocation_deadline_required", "Trusted remaining time is invalid.", 503)
    return min(25.0, value / 1000)

NOTICE = ('<aside class="notice" aria-label="Provider and persistence scope">'
          'Explicit private adapter composition. The displayed provider mode '
          'distinguishes disconnected, injected mock, and configured but '
          'unverified transport. A locally validated candidate does not prove '
          'Nebius execution, entitlement, billing or competition acceptance. '
          'Budget reservations are not provider receipts.</aside>')


class BoundNebiusDomain(NebiusDomain):
    def __init__(self, triage, proposals, *, transport=None, api_key=None,
                 mode="disconnected", attempt_store=None):
        super().__init__(triage, proposals)
        self._status = ProposalService.describe(mode)
        if mode == "disconnected":
            if transport is not None or api_key is not None or attempt_store is not None:
                raise ValueError("Disconnected mode accepts no execution binding.")
        elif not callable(transport) or not isinstance(api_key, str) or not api_key or attempt_store is None:
            raise ValueError("An enabled domain needs explicit transport, key and attempt store.")
        if mode != "disconnected" and not (
                inspect.iscoroutinefunction(transport)
                or inspect.iscoroutinefunction(getattr(transport, "__call__", None))):
            raise ValueError("The explicit single-request transport must be async.")
        if mode != "disconnected" and not all(
                callable(getattr(attempt_store, method, None)) for method in ("claim", "finish")):
            raise ValueError("An explicit claim/finish attempt store is required.")
        self._transport, self._key, self._store, self.mode = transport, api_key, attempt_store, mode
        self._cloud_quota = None

    def get(self, path):
        return dict(self._status) if path == "/api/provider" else super().get(path)

    def preflight(self, path, packet):
        if path == "/api/propose":
            try:
                validate_packet(packet)
            except InputError:
                raise EdgeError("invalid_source", "Invalid or stale authored-case request. Reload and inspect its source.") from None

    def use_provider(self, path):
        return path == "/api/propose" and self.mode != "disconnected"

    def post_with_permit(self, path, packet, permit):
        if path != "/api/propose":
            return super().post(path, packet)
        if self.mode == "disconnected":
            return asyncio.run(ProposalService().propose(packet))
        if not isinstance(permit, RequestPermit) or permit.app_id != "nebius" or permit.raw_reserved != 1:
            raise EdgeError("reservation_rejected", "One fresh precharged Nebius attempt is required.", 503)

        async def guarded_transport(**kwargs):
            if self._cloud_quota is not None:
                self._cloud_quota.require_budget(TIMEOUT_SECONDS + self._cloud_quota.policy.pacing_ms / 1000 + 1)
            # Adapter owns endpoint/model/body validation. This boundary enforces
            # the exact single-request transport envelope and consumes BEFORE IO.
            if (set(kwargs) != {"url", "headers", "body", "timeout_seconds", "max_response_bytes"}
                    or kwargs["url"] != ENDPOINT
                    or kwargs["timeout_seconds"] != TIMEOUT_SECONDS
                    or kwargs["max_response_bytes"] != MAX_RESPONSE_BYTES
                    or not isinstance(kwargs["body"], bytes)):
                raise ValueError("Unexpected raw transport contract")
            descriptor = digest({"endpoint": kwargs["url"],
                                 "body_sha256": hashlib.sha256(kwargs["body"]).hexdigest(),
                                 "timeout_seconds": kwargs["timeout_seconds"],
                                 "max_response_bytes": kwargs["max_response_bytes"]})
            return await permit.invoke_raw_async(descriptor, lambda: self._transport(**kwargs))

        service = ProposalService(transport=guarded_transport, api_key=self._key,
                                  mode=self.mode, attempt_store=self._store,
                                  dispatch_count=lambda: permit.calls_started)
        try:
            return asyncio.run(service.propose(packet))
        except InputError:
            raise EdgeError("invalid_source", "Request ID or authored source changed. No replacement attempt is allowed.", 409) from None


class NebiusComposition(DemoHandler):
    """Synchronous Lambda-shaped boundary; never drives an existing async loop."""
    def _index(self, now):
        response = super()._index(now)
        response["body"] = response["body"].replace(V2_NOTICE, NOTICE, 1)
        return response

    def __call__(self, event, context=None):
        permit = None
        invocation_token = None
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
            self.domain.preflight(path, packet)
            try:
                asyncio.get_running_loop()
            except RuntimeError:
                pass
            else:
                raise EdgeError("async_boundary", "Use the synchronous isolated request boundary.", 503)
            if self.quota is None:
                raise EdgeError("quota_unconfigured", "Shared request allowance is not configured. No action started.", 503)
            fingerprint = digest({"app": "nebius", "path": path, "revision": self.config.source_revision,
                                  "session": hashlib.sha256(session.encode()).hexdigest(),
                                  "body": hashlib.sha256(body).hexdigest()})
            use_provider = self.domain.use_provider(path)
            if getattr(self, "require_cloud_deadline", False):
                invocation_token = _INVOCATION.set(context)
                required = TIMEOUT_SECONDS + 2 * self.quota.policy.pacing_ms / 1000 + 2 if use_provider else 2
                if _remaining_invocation_seconds() < required:
                    raise EdgeError("invocation_budget_insufficient", "Insufficient invocation time; no budget or provider action started.", 503)
            permit = self.quota.reserve(request_id, fingerprint, use_provider=use_provider)
            if (not isinstance(permit, RequestPermit) or permit.app_id != "nebius"
                    or permit.fingerprint != fingerprint or permit.raw_reserved != int(use_provider)):
                raise EdgeError("reservation_rejected", "The fresh request budget does not match this action.", 503)
            return self._response(200, self.domain.post_with_permit(path, packet, permit))
        except EdgeError as error:
            return self._response(error.status, {"error": {"code": error.code, "message": error.message}})
        except Exception as error:
            if error.__class__.__name__ == "QuotaError" and isinstance(getattr(error, "code", None), str):
                code = error.code if re.fullmatch(r"[a-z_]{1,60}", error.code) else "quota_unavailable"
                status = error.status if type(getattr(error, "status", None)) is int and 400 <= error.status <= 599 else 503
                message = ("No action started. Wait at least two seconds, then click again explicitly. Automatic retries are disabled."
                           if code == "quota_paced" else "Shared allowance or prior reservation needs review. Do not automatically retry.")
                return self._response(status, {"error": {"code": code, "message": message}})
            return self._response(503, {"error": {"code": "demo_unavailable", "message": "Request unavailable. Inspect any prior attempt; do not automatically retry."}})
        finally:
            if isinstance(permit, RequestPermit):
                permit.close()
            if invocation_token is not None:
                _INVOCATION.reset(invocation_token)


def make_nebius_handler(config, *, index_html, quota=None, signing_key,
                        transport=None, api_key=None, mode="disconnected",
                        attempt_store=None, clock=time.time, random_bytes=None):
    if not isinstance(config, EdgeConfig) or config.app_id != "nebius":
        raise ValueError("This composition supports only Nebius. Qloo remains unbound.")
    import proposal_service
    import triage
    domain = BoundNebiusDomain(triage, proposal_service, transport=transport,
                              api_key=api_key, mode=mode, attempt_store=attempt_store)
    options = {} if random_bytes is None else {"random_bytes": random_bytes}
    return NebiusComposition(config, index_html=index_html, domain=domain, quota=quota,
                             signing_key=signing_key, clock=clock, **options)


def handler(event, context=None):
    """No implicit binding, environment reads, SDK construction or live enablement."""
    return {"statusCode": 503, "headers": {**SECURITY, "content-type": "application/json; charset=utf-8"},
            "body": canonical({"error": "Private composition is not configured. No provider request is available.",
                               "error_code": "binding_unconfigured"}), "isBase64Encoded": False}
