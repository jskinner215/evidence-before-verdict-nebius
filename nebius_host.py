"""Explicit private async lifecycle candidate; import starts no thread or I/O.

One process host, one admitted operation and one executor job. An OS resolver
thread cannot be killed: a timed-out job blocks further admission until it ends,
and close reports pending rather than claiming bounded process termination.
"""
import asyncio
from concurrent.futures import ThreadPoolExecutor
from contextvars import ContextVar, copy_context
from dataclasses import dataclass
import inspect
import math
import threading
import time


_PROCESS_SLOT = threading.Lock()
_SCOPE = ContextVar("private_nebius_async_scope", default=None)
MAX_ASYNC_TASKS = 16


class HostRefusal(RuntimeError):
    pass


class HostTimeout(TimeoutError):
    pass


class _Executor(ThreadPoolExecutor):
    def __init__(self, changed):
        super().__init__(max_workers=1, thread_name_prefix="nebius-bounded-executor")
        self._guard = threading.Lock()
        self.pending = 0
        self._changed = changed
        self._idle = threading.Event()
        self._idle.set()

    def submit(self, fn, /, *args, **kwargs):
        with self._guard:
            if self.pending:
                raise HostRefusal("The bounded executor is occupied; no job was queued.")
            self.pending = 1
            self._idle.clear()
        try:
            future = super().submit(fn, *args, **kwargs)
        except BaseException:
            with self._guard:
                self.pending = 0
                self._idle.set()
            raise

        def finished(_future):
            with self._guard:
                self.pending = 0
                self._idle.set()
            self._changed()
        future.add_done_callback(finished)
        return future

    def wait_idle(self, timeout_seconds):
        """Acknowledge registry retirement, not cancellation of a remote job."""
        if not self._idle.wait(timeout_seconds):
            return False
        with self._guard:
            return self.pending == 0


class RequestScope:
    def __init__(self, deadline):
        self.deadline = deadline
        self.cancelled = threading.Event()

    def remaining(self):
        if self.cancelled.is_set():
            raise HostTimeout("The operation was cancelled; execution is uncertain.")
        left = self.deadline - time.monotonic()
        if left <= 0:
            raise HostTimeout("The operation deadline expired; no retry is authorized.")
        return left


def current_scope():
    scope = _SCOPE.get()
    if not isinstance(scope, RequestScope):
        raise HostRefusal("Use the explicit owned persistent async host.")
    scope.remaining()
    return scope


@dataclass(frozen=True)
class CloseStatus:
    stopped: bool
    pending_executor_jobs: int
    pending_operation: bool


class _Invocation:
    def __init__(self, factory, deadline, context):
        self.factory, self.context = factory, context
        self.scope = RequestScope(deadline)
        self.done = threading.Event()
        self.task = None
        self.value = None
        self.error = None


class PersistentAsyncHost:
    """Small non-queuing host, not a web server or Lambda bootstrap.

    Timeout includes a cleanup reserve. If trusted coroutine cleanup fails to
    finish, the caller returns a refusal and the host is poisoned. Pending DNS
    work is not retried, hidden, or multiplied by creating another host.
    """
    def __init__(self, *, startup_wait_seconds=2.0):
        if (type(startup_wait_seconds) not in (int, float) or not math.isfinite(startup_wait_seconds)
                or not 0 < startup_wait_seconds <= 2):
            raise HostRefusal("Use a positive startup wait no greater than two seconds.")
        self._startup_wait = startup_wait_seconds
        self._admission = threading.Lock()
        self._ready = threading.Event()
        self._thread = None
        self._loop = None
        self._executor = None
        self._active = None
        self._closing = False
        self._poisoned = False
        self._startup_failed = False
        self._tasks = set()

    def __repr__(self):
        return "PersistentAsyncHost(explicit_lifecycle=True)"

    def start(self):
        if self._thread is not None or self._closing:
            raise HostRefusal("The host cannot be started again.")
        if not _PROCESS_SLOT.acquire(blocking=False):
            raise HostRefusal("A process host is already active or still draining.")
        self._thread = threading.Thread(target=self._main, daemon=True,
                                        name="nebius-owned-event-loop")
        try:
            self._thread.start()
        except BaseException:
            _PROCESS_SLOT.release()
            raise
        if not self._ready.wait(self._startup_wait) or self._startup_failed:
            self._closing = True
            self._changed()
            raise HostRefusal("The explicit event loop did not become ready.")
        return self

    def _changed(self):
        loop = self._loop
        if loop is not None and not loop.is_closed():
            try:
                loop.call_soon_threadsafe(self._maybe_stop)
            except RuntimeError:
                pass

    def _main(self):
        try:
            self._loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self._loop)
            self._executor = _Executor(self._changed)
            self._loop.set_default_executor(self._executor)
            self._loop.set_task_factory(self._task_factory)
            self._ready.set()
            self._loop.call_soon(self._maybe_stop)
            self._loop.run_forever()
        except BaseException:
            self._startup_failed = True
            self._ready.set()
        finally:
            # Only _maybe_stop stops a healthy loop, after tasks and executor
            # callables finish. No shutdown_default_executor on each request.
            if self._loop is not None:
                self._loop.close()
            if self._executor is not None:
                self._executor.shutdown(wait=True, cancel_futures=True)
            _PROCESS_SLOT.release()

    def _task_factory(self, loop, coroutine, context=None):
        if self._closing or len(self._tasks) >= MAX_ASYNC_TASKS:
            if inspect.iscoroutine(coroutine):
                coroutine.close()
            raise HostRefusal("The bounded task lifecycle is closing or full.")
        task = asyncio.Task(coroutine, loop=loop, context=context)
        self._tasks.add(task)
        def finished(done):
            try:
                # Do not let an unjoined descendant's arbitrary exception
                # representation reach the default event-loop stderr handler.
                if not done.cancelled():
                    done.exception()
            except BaseException:
                pass
            self._tasks.discard(done)
            self._maybe_stop()
        task.add_done_callback(finished)
        return task

    def _maybe_stop(self):
        if not self._closing or self._executor.pending:
            return
        if any(not task.done() for task in asyncio.all_tasks(self._loop)):
            return
        self._loop.stop()

    def _begin_close(self):
        for task in tuple(self._tasks):
            if not task.done():
                task.cancel()
        self._maybe_stop()

    async def _execute(self, invocation, work_deadline):
        token = _SCOPE.set(invocation.scope)
        try:
            invocation.scope.remaining()
            async with asyncio.timeout_at(work_deadline):
                operation = invocation.factory()
                if not inspect.isawaitable(operation):
                    raise HostRefusal("The operation factory must return an awaitable.")
                invocation.value = await operation
        except (TimeoutError, asyncio.CancelledError):
            invocation.scope.cancelled.set()
            invocation.error = HostTimeout("Operation timed out; execution is uncertain and no retry occurred.")
        except BaseException:
            # Never return arbitrary exception text, request headers or locals.
            invocation.error = HostRefusal("The private async operation failed; inspect sanitized evidence.")
        finally:
            # A descendant task has a copied ContextVar but shares this scope.
            # Revoking it prevents post-response credential reads/network starts.
            invocation.scope.cancelled.set()
            _SCOPE.reset(token)
            invocation.done.set()
            self._loop.call_soon(self._maybe_stop)

    def _schedule(self, invocation, work_seconds):
        if self._closing or self._poisoned or invocation.scope.cancelled.is_set():
            invocation.error = HostRefusal("The host is closing or unavailable.")
            invocation.done.set()
            self._maybe_stop()
            return
        if any(not task.done() for task in self._tasks):
            invocation.scope.cancelled.set()
            invocation.error = HostRefusal("Earlier async work is still draining; no operation was queued.")
            invocation.done.set()
            return
        try:
            invocation.task = self._loop.create_task(
                self._execute(invocation, self._loop.time() + work_seconds),
                context=invocation.context)
        except BaseException:
            invocation.scope.cancelled.set()
            invocation.error = HostRefusal("The bounded async task could not be admitted.")
            invocation.done.set()
            self._maybe_stop()

    def _cancel(self, invocation):
        invocation.scope.cancelled.set()
        if invocation.task is not None and not invocation.task.done():
            invocation.task.cancel()

    def run(self, operation_factory, *, timeout_seconds=24.0):
        if (not callable(operation_factory) or type(timeout_seconds) not in (int, float)
                or not math.isfinite(timeout_seconds) or not 0 < timeout_seconds <= 24):
            raise HostRefusal("Use an explicit factory and a positive deadline no greater than twenty-four seconds.")
        if self._thread is None or self._loop is None or not self._thread.is_alive():
            raise HostRefusal("Start the explicit host before admission.")
        if threading.current_thread() is self._thread:
            raise HostRefusal("Do not synchronously re-enter the owned event loop.")
        if not self._admission.acquire(blocking=False):
            raise HostRefusal("Another operation is admitted; no request was queued.")
        try:
            if self._closing or self._poisoned or self._executor.pending:
                raise HostRefusal("The host is unavailable or still draining; no request was queued.")
            deadline = time.monotonic() + timeout_seconds
            invocation = _Invocation(operation_factory, deadline, copy_context())
            self._active = invocation
            reserve = min(0.25, timeout_seconds / 4)
            self._loop.call_soon_threadsafe(self._schedule, invocation, timeout_seconds - reserve)
            if not invocation.done.wait(max(0, deadline - time.monotonic())):
                self._poisoned = True
                invocation.scope.cancelled.set()
                self._loop.call_soon_threadsafe(self._cancel, invocation)
                raise HostTimeout("Operation cleanup exceeded its budget; host is poisoned and execution is uncertain.")
            if time.monotonic() >= deadline:
                raise HostTimeout("Operation deadline expired; no retry occurred.")
            if invocation.error is not None:
                raise invocation.error
            return invocation.value
        finally:
            self._active = None
            self._admission.release()

    def close(self, *, timeout_seconds=0.5):
        if type(timeout_seconds) not in (int, float) or not math.isfinite(timeout_seconds) or not 0 <= timeout_seconds <= 2:
            raise HostRefusal("Use a bounded close wait no greater than two seconds.")
        if threading.current_thread() is self._thread:
            raise HostRefusal("Close the host from its synchronous owning thread.")
        self._closing = True
        if self._thread is None:
            return CloseStatus(True, 0, False)
        invocation = self._active
        if invocation is not None:
            invocation.scope.cancelled.set()
            self._loop.call_soon_threadsafe(self._cancel, invocation)
        if self._loop is not None and not self._loop.is_closed():
            try:
                self._loop.call_soon_threadsafe(self._begin_close)
            except RuntimeError:
                pass
        self._thread.join(timeout_seconds)
        return CloseStatus(not self._thread.is_alive(),
                           self._executor.pending if self._executor else 0,
                           bool(invocation and not invocation.done.is_set()))
