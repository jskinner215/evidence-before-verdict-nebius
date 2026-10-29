"""Explicit caller-loop binding; no SDK, credentials, loop or store on import.

This isolated continuation does not alter or activate the frozen cloud handler.
The caller supplies an already-reserved fresh permit and reviewed durable store.
"""
import asyncio
import hashlib
import math
import re

from global_quota_v2 import RequestPermit
import nebius_adapter as adapter
import nebius_http
from proposal_service import ProposalService, validate_packet
from triage import digest


class BindingRefusal(RuntimeError):
    pass


def _header_safe_key(value):
    return (isinstance(value, str) and 1 <= len(value) <= 4096
            and all(33 <= ord(char) <= 126 for char in value))


class _ClaimObservation:
    """Observe only the real claim return; never manufacture durable authority."""
    __slots__ = ("store", "claimed")

    def __init__(self, store):
        self.store, self.claimed = store, False

    def claim(self, request_id, source_key):
        answer = self.store.claim(request_id, source_key)
        self.claimed = (isinstance(answer, tuple) and len(answer) == 2
                        and answer[0] == "claimed" and answer[1] is None)
        # Preserve the service's original conflict/pending/complete handling.
        return answer

    def finish(self, request_id, source_key, receipt):
        return self.store.finish(request_id, source_key, receipt)


class _AttemptBinding:
    """One service invocation, one lazy one-shot transport, no reset or retry."""
    __slots__ = ("observation", "permit", "guard", "session_factory", "enabled", "attempt", "used")

    def __init__(self, store, permit, guard, session_factory, enabled):
        self.observation = _ClaimObservation(store)
        self.permit, self.guard = permit, guard
        self.session_factory, self.enabled = session_factory, enabled
        self.attempt, self.used = None, False

    def dispatch_count(self):
        return 0 if self.attempt is None else self.attempt.dispatch_count()

    def _admitted(self):
        return (self.observation.claimed and self.enabled is True
                and self.permit.calls_started == 1 and self.guard() is True)

    async def transport(self, **kwargs):
        if self.used or not self.observation.claimed or self.attempt is not None:
            raise BindingRefusal("A fresh durable claim is required; no transport retry is allowed.")
        # One callback entry at most, including a permit/precondition refusal.
        self.used = True
        try:
            admitted = self.enabled is True and self.guard() is True
        except Exception:
            admitted = False
        if not admitted:
            raise BindingRefusal("Local binding admission refused before permit entry.")
        if (set(kwargs) != {"url", "headers", "body", "timeout_seconds", "max_response_bytes"}
                or kwargs["url"] != adapter.ENDPOINT
                or kwargs["timeout_seconds"] != adapter.TIMEOUT_SECONDS
                or kwargs["max_response_bytes"] != adapter.MAX_RESPONSE_BYTES
                or not isinstance(kwargs["body"], bytes)
                or not isinstance(kwargs["headers"], dict)
                or set(kwargs["headers"]) != {"Authorization", "Content-Type"}
                or kwargs["headers"]["Content-Type"] != "application/json"
                or not isinstance(kwargs["headers"]["Authorization"], str)
                or not kwargs["headers"]["Authorization"].startswith("Bearer ")
                or not _header_safe_key(kwargs["headers"]["Authorization"][7:])):
            raise BindingRefusal("Unexpected raw transport envelope.")
        descriptor = digest({"endpoint": kwargs["url"],
            "body_sha256": hashlib.sha256(kwargs["body"]).hexdigest(),
            "timeout_seconds": kwargs["timeout_seconds"],
            "max_response_bytes": kwargs["max_response_bytes"]})

        async def dispatch():
            # invoke_raw_async consumes its callback-entry budget first. The
            # HTTP object's distinct private counter remains zero until POST.
            self.attempt = nebius_http.make_post_attempt(admission_check=self._admitted,
                enabled=self.enabled, session_factory=self.session_factory)
            return await self.attempt(**kwargs)

        return await self.permit.invoke_raw_async(descriptor, dispatch)


class AsyncProposalRunner:
    """Serial proposals on one existing caller-owned event loop.

    No executor, event-loop thread, process, SDK or credential loader is created.
    Cancellation keeps the durable pending fence. A non-cooperative child may
    outlive the bounded join; the runner then permanently refuses replacements.
    It never claims to stop remote inference or billing.
    """
    def __init__(self, *, attempt_store, api_key, admission_check, enabled=False,
                 session_factory=None, cancel_join_seconds=0.25):
        if (not all(callable(getattr(attempt_store, name, None)) for name in ("claim", "finish"))
                or not isinstance(api_key, str) or not api_key
                or not callable(admission_check) or type(enabled) is not bool
                or (session_factory is not None and not callable(session_factory))
                or type(cancel_join_seconds) not in (int, float)
                or not math.isfinite(cancel_join_seconds) or not 0 < cancel_join_seconds <= 1):
            raise BindingRefusal("Explicit bounded private dependencies are required.")
        self._store, self._key, self._guard = attempt_store, api_key, admission_check
        self._enabled, self._factory, self._join = enabled, session_factory, cancel_join_seconds
        self._loop, self._task, self._closing, self._cancel_requested = None, None, False, None

    def _caller_loop(self):
        loop = asyncio.get_running_loop()
        if self._loop is None:
            self._loop = loop
        elif self._loop is not loop:
            raise BindingRefusal("Use the original caller-owned event loop.")
        return loop

    def status(self):
        return {"closed": self._closing, "pending_task": self._task is not None and not self._task.done(),
                "provider_execution_verified": False}

    def preflight(self):
        """Cheap local check; no loop, durable claim, key lookup or quota refund.

        A trusted outer edge may call this BEFORE its quota reservation. Calling
        propose() with an already-precharged permit cannot undo that reservation.
        This is rechecked before claim and at both transport admission boundaries.
        """
        try:
            admitted = (not self._closing and self._enabled is True
                        and _header_safe_key(self._key) and self._guard() is True)
        except Exception:
            admitted = False
        if not admitted:
            raise BindingRefusal("Local binding is disabled or invalid; no new durable claim started.")
        return True

    async def _one(self, packet, permit):
        try:
            self.preflight()
            binding = _AttemptBinding(self._store, permit,
                lambda: not self._closing and self._guard() is True, self._factory, self._enabled)
            service = ProposalService(transport=binding.transport, api_key=self._key,
                mode="configured_unverified", attempt_store=binding.observation,
                dispatch_count=binding.dispatch_count)
            return await service.propose(packet)
        finally:
            permit.close()

    async def _cancel_join(self, task):
        # One cancellation request only. Re-cancelling while __aexit__ awaits
        # cleanup can interrupt the very resource closure we are joining.
        if not task.done() and self._cancel_requested is not task:
            self._cancel_requested = task
            task.cancel()
        done, _ = await asyncio.wait({task}, timeout=self._join)
        if task not in done:
            self._closing = True
            return False
        # Retrieve a finished exception so shutdown cannot leak task warnings.
        if not task.cancelled():
            task.exception()
        return True

    async def propose(self, packet, *, permit, action_fingerprint):
        loop = self._caller_loop()
        if self._closing or (self._task is not None and not self._task.done()):
            raise BindingRefusal("Runner is closed or has an unresolved task; no replacement started.")
        validate_packet(packet)
        if (not isinstance(action_fingerprint, str) or not re.fullmatch(r"[0-9a-f]{64}", action_fingerprint)
                or type(permit) is not RequestPermit or permit.app_id != "nebius"
                or permit.fingerprint != action_fingerprint
                or permit.raw_reserved != 1 or permit.calls_started != 0):
            raise BindingRefusal("One fresh precharged Nebius permit matching the trusted action is required.")
        try:
            self.preflight()
        except BindingRefusal:
            permit.close()
            raise
        task = loop.create_task(self._one(packet, permit))
        self._task, self._cancel_requested = task, None
        try:
            return await asyncio.shield(task)
        except asyncio.CancelledError:
            self._closing = True
            try:
                await self._cancel_join(task)
            finally:
                # Cancellation is not proof that a remote request stopped.
                if not task.done():
                    self._closing = True
            raise
        finally:
            # A child cancelled before its first scheduled step never enters
            # _one's finally. The accepting outer owner must close its lease too.
            permit.close()
            if task.done() and self._task is task:
                self._task = None

    async def aclose(self):
        self._caller_loop()
        self._closing = True
        task = self._task
        if task is None:
            return {"closed": True, "pending_task": False}
        if not task.done():
            await self._cancel_join(task)
        if task.done():
            if not task.cancelled():
                task.exception()
            if self._task is task:
                self._task = None
        return {"closed": True, "pending_task": self._task is not None}
