"""Private one-shot Nebius v8 HTTP continuation; no client/key/network on import.

The caller owns the running event loop, durable admission and a fresh attempt
object. This file loads no environment, credentials or SDK. It activates no
handler. The HTTP-entry counter is conservative local instrumentation, never
proof that bytes reached a server or that billing/model execution occurred.
"""
from contextlib import asynccontextmanager
import hashlib
import json
import math
import threading
import sys

import nebius_adapter as adapter
from triage import CASES, strict_json

ENDPOINT='https://api.tokenfactory.nebius.com/v1/chat/completions'
HOST='api.tokenfactory.nebius.com'
MODEL='nvidia/Nemotron-3.5-Super-VL'
MAX_REQUEST_BYTES=8192
MAX_RESPONSE_BYTES=16384
MAX_SECONDS=15
MAX_HEADERS=32
MAX_HEADER_FIELD=1024
MAX_HEADER_BYTES=8192
CHUNK_BYTES=1024
REVIEWED_AIOHTTP_VERSION='3.13.5'
# Exact Linux source pin. The real factory refuses other platforms before
# SDK import or session construction; injected synthetic sessions remain portable.
REVIEWED_CLIENT_SOURCE_SHA256='2641c6aeb26ad69488ed0109c348d92b1e532cbcccf3ba1ff18c7eeb69b8c7a8'


class TransportRefusal(RuntimeError):
    pass


def _contract():
    if (adapter.ENDPOINT!=ENDPOINT or adapter.MODEL!=MODEL or adapter.TIMEOUT_SECONDS!=MAX_SECONDS
            or adapter.MAX_REQUEST_BYTES!=MAX_REQUEST_BYTES or adapter.MAX_RESPONSE_BYTES!=MAX_RESPONSE_BYTES
            or adapter.MAX_OUTPUT_TOKENS!=512):
        raise TransportRefusal('The imported adapter differs from the reviewed v8 contract.')


def _json_no_secret(body,key,*,limit=MAX_RESPONSE_BYTES):
    try:value=strict_json(body.decode('utf-8'),max_bytes=limit)
    except Exception:raise TransportRefusal('Expected bounded JSON; content withheld.') from None
    pending=[(value,0)];count=0
    while pending:
        value,depth=pending.pop();count+=1
        if depth>32 or count>4096:raise TransportRefusal('JSON structure exceeds its bound.')
        if isinstance(value,str) and key in value:raise TransportRefusal('Credential echo withheld.')
        if isinstance(value,dict):pending.extend((v,depth+1) for pair in value.items() for v in pair)
        elif isinstance(value,list):pending.extend((v,depth+1) for v in value)


def _request(url,headers,body,seconds,limit):
    _contract()
    if url!=ENDPOINT or not isinstance(url,str):raise TransportRefusal('Only the exact reviewed POST endpoint is accepted.')
    if (not isinstance(headers,dict) or set(headers)!={'Authorization','Content-Type'}
            or headers['Content-Type']!='application/json' or not isinstance(headers['Authorization'],str)
            or not headers['Authorization'].startswith('Bearer ')):
        raise TransportRefusal('Only the exact reviewed request headers are accepted.')
    key=headers['Authorization'][7:]
    if not 1<=len(key)<=4096 or any(ord(c)<=32 or ord(c)>=127 for c in key):raise TransportRefusal('A bounded header-safe explicit key is required.')
    if (not isinstance(body,bytes) or not 1<=len(body)<=MAX_REQUEST_BYTES
            or type(seconds) not in (int,float) or not math.isfinite(seconds) or not 0<seconds<=MAX_SECONDS
            or type(limit) is not int or not 0<limit<=MAX_RESPONSE_BYTES):
        raise TransportRefusal('Use the reviewed bounded request envelope.')
    if not any(body==adapter.request_body(case['id']) for case in CASES):raise TransportRefusal('Only exact current authored-case request bytes are accepted.')
    if key.encode('ascii') in body or key in url:raise TransportRefusal('A credential cannot appear in the URL or request data.')
    _json_no_secret(body,key,limit=MAX_REQUEST_BYTES)
    return key


def _response_headers(raw):
    if not isinstance(raw,(tuple,list)) or len(raw)>MAX_HEADERS:raise TransportRefusal('Response header count exceeds its bound.')
    total=0
    for row in raw:
        if not isinstance(row,tuple) or len(row)!=2 or any(not isinstance(v,bytes) for v in row):raise TransportRefusal('Unexpected response header shape.')
        if len(row[0])+len(row[1])>MAX_HEADER_FIELD:raise TransportRefusal('Response header field exceeds its bound.')
        total+=len(row[0])+len(row[1])+4
    if total>MAX_HEADER_BYTES:raise TransportRefusal('Response headers exceed their aggregate bound.')


def _final_url(response):
    from yarl import URL
    actual=getattr(response,'url',None)
    if (type(actual) is not URL or actual!=URL(ENDPOINT) or actual.scheme!='https' or actual.raw_authority!=HOST
            or actual.raw_user is not None or actual.raw_password is not None or actual.explicit_port is not None or actual.raw_fragment):
        raise TransportRefusal('Final response URL differs from the approved endpoint.')


@asynccontextmanager
async def _new_session(seconds):
    if sys.platform!='linux':raise TransportRefusal('The real session factory supports only the reviewed Linux runtime.')
    if type(seconds) not in (int,float) or not math.isfinite(seconds) or not 0<seconds<=MAX_SECONDS:raise TransportRefusal('A bounded real-session deadline is required.')
    from importlib.metadata import distribution,version
    from pathlib import Path
    if version('aiohttp')!=REVIEWED_AIOHTTP_VERSION:raise TransportRefusal('HTTP dependency version differs from the reviewed source.')
    client_source=distribution('aiohttp').locate_file('aiohttp/client.py').resolve()
    if hashlib.sha256(client_source.read_bytes()).hexdigest()!=REVIEWED_CLIENT_SOURCE_SHA256:raise TransportRefusal('HTTP retry source pin differs.')
    import ssl
    import aiohttp
    if Path(aiohttp.client.__file__).resolve()!=client_source:raise TransportRefusal('Loaded HTTP implementation differs.')
    tls=ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH);tls.check_hostname=True;tls.verify_mode=ssl.CERT_REQUIRED;tls.minimum_version=ssl.TLSVersion.TLSv1_2
    connector=aiohttp.TCPConnector(ssl=tls,limit=1,limit_per_host=1,force_close=True,use_dns_cache=False,timeout_ceil_threshold=60,ssl_shutdown_timeout=0)
    timeout=aiohttp.ClientTimeout(total=seconds,connect=seconds,sock_connect=seconds,sock_read=seconds,ceil_threshold=60)
    try:
        async with aiohttp.ClientSession(connector=connector,timeout=timeout,trust_env=False,cookie_jar=aiohttp.DummyCookieJar(),auto_decompress=False,
                read_bufsize=CHUNK_BYTES,max_line_size=MAX_HEADER_FIELD,max_field_size=MAX_HEADER_FIELD,max_headers=MAX_HEADERS,
                raise_for_status=False,middlewares=(),trace_configs=[],skip_auto_headers={'User-Agent'},ssl_shutdown_timeout=0) as session:
            if getattr(session,'_retry_connection',None) is not True:raise TransportRefusal('Unexpected HTTP retry policy.')
            session._retry_connection=False
            if session._retry_connection is not False:raise TransportRefusal('HTTP retries were not disabled.')
            yield session
    finally:await connector.close(abort_ssl=True)


class PostAttempt:
    """One object per admitted durable attempt; counter has no public reset.

    A count of1 means the local POST API was entered or about to be entered.
    It never proves network delivery, provider execution or cost. A count of0
    means that boundary was not reached by this trusted implementation.
    Python reflection and trusted injected factories are not a security sandbox.
    """
    __slots__=('__admission','__enabled','__factory','__lock','__claimed','__dispatches')
    def __init__(self,*,admission_check,enabled=False,session_factory=None):
        if not callable(admission_check) or type(enabled) is not bool or (session_factory is not None and not callable(session_factory)):
            raise TransportRefusal('Explicit trusted admission and session dependencies are required.')
        self.__admission,self.__enabled,self.__factory=admission_check,enabled,session_factory
        self.__lock=threading.Lock();self.__claimed=False;self.__dispatches=0
    def dispatch_count(self):
        with self.__lock:return self.__dispatches
    async def __call__(self,*,url,headers,body,timeout_seconds,max_response_bytes):
        import asyncio
        entered=asyncio.get_running_loop().time()
        with self.__lock:
            if self.__claimed:raise TransportRefusal('This one-shot attempt is already consumed; no retry occurred.')
            self.__claimed=True
        try:
            if self.__enabled is not True or self.__admission() is not True:raise TransportRefusal('Transport remains disabled or unadmitted.')
            key=_request(url,headers,body,timeout_seconds,max_response_bytes)
            loop=asyncio.get_running_loop();deadline=entered+timeout_seconds
            if loop.time()>=deadline:raise TimeoutError()
            async with asyncio.timeout_at(deadline):
                factory=self.__factory or _new_session
                async with factory(timeout_seconds) as session:
                    if getattr(session,'closed',None) is not False:raise TransportRefusal('An open caller-owned session is required.')
                    if self.__admission() is not True:raise TransportRefusal('Admission changed before POST.')
                    # A synchronous guard can consume time or close its session.
                    # Recheck both AFTER it returns, before counter/HTTP entry.
                    if getattr(session,'closed',None) is not False:raise TransportRefusal('Session closed before POST.')
                    if loop.time()>=deadline:raise TimeoutError()
                    outgoing={'Authorization':'Bearer '+key,'Content-Type':'application/json','Accept':'application/json','Accept-Encoding':'identity'}
                    # Mark before entering the HTTP API; local exceptions there
                    # cannot later be relabeled as known no-dispatch.
                    with self.__lock:self.__dispatches=1
                    async with session.post(ENDPOINT,headers=outgoing,data=body,allow_redirects=False,proxy=None,read_until_eof=False) as response:
                        try:
                            _final_url(response);_response_headers(response.raw_headers)
                            if type(response.status) is not int or not 100<=response.status<=599:raise TransportRefusal('Unexpected status.')
                            if response.status!=200:answer=adapter.TransportResponse(response.status,b'')
                            else:
                                if response.headers.get('Content-Encoding','identity').lower() not in ('','identity'):raise TransportRefusal('Compressed content is refused.')
                                if response.headers.get('Content-Type','').split(';')[0].strip().lower()!='application/json':raise TransportRefusal('Expected JSON content type.')
                                length=response.content_length
                                if length is not None and (type(length) is not int or not 0<=length<=max_response_bytes):raise TransportRefusal('Advertised response exceeds its bound.')
                                received=bytearray()
                                async for chunk in response.content.iter_chunked(CHUNK_BYTES):
                                    if not isinstance(chunk,bytes) or len(received)+len(chunk)>max_response_bytes:raise TransportRefusal('Response exceeds its byte bound.')
                                    received.extend(chunk)
                                raw=bytes(received)
                                if length is not None and len(raw)!=length:raise TransportRefusal('Received length differs from its advertised bound.')
                                if key.encode('ascii') in raw:raise TransportRefusal('Credential echo withheld.')
                                _json_no_secret(raw,key);answer=adapter.TransportResponse(200,raw)
                        finally:response.close()
                    if getattr(response,'closed',None) is not True:raise TransportRefusal('Response did not close.')
                if getattr(session,'closed',None) is not True:raise TransportRefusal('Session did not close.')
                if loop.time()>=deadline:raise TimeoutError()
                return answer
        except asyncio.CancelledError:raise
        except TimeoutError:raise TimeoutError('HTTP deadline expired; inspect the private counter. No retry occurred.') from None
        except Exception:raise TransportRefusal('HTTP attempt refused or failed; inspect the private counter. No retry occurred.') from None


def make_post_attempt(*,admission_check,enabled=False,session_factory=None):
    """Inert construction, not user authorization or activation of any handler."""
    return PostAttempt(admission_check=admission_check,enabled=enabled,session_factory=session_factory)
