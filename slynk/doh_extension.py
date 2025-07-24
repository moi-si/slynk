import base64
import asyncio
import dns.message
import dns.rdatatype
import aiohttp
from aiohttp_socks import ProxyConnector, ProxyType

from .logger_with_context import logger
logger = logger.getChild('dns_resolver')


class ProxiedDoHClient:
    __slots__ = (
        'dns_url',
        'proxy_type',
        'proxy_host',
        'proxy_port',
        'session',
        'header'
    )

    def __init__(self, dns_url, proxy_type, proxy_host, proxy_port):
        self.dns_url = dns_url
        self.proxy_type = proxy_type
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port
        self.session = None
        self.header = {'Accept': 'application/dns-message'}

    async def init_session(self):
        if self.proxy_type == 'socks5':
            proxy_type = ProxyType.SOCKS5
        elif self.proxy_type == 'http':
            proxy_type = ProxyType.HTTP
        else:
            raise ValueError(f'Invalid proxy type: {self.proxy_type}')

        connector = ProxyConnector(
            proxy_type=proxy_type,
            host=self.proxy_host,
            port=self.proxy_port,
            rdns=True
        )
        self.session = aiohttp.ClientSession(connector=connector)

    async def close_session(self):
        if self.session:
            await self.session.close()
            self.session = None

    async def resolve(self, domain, qtype):
        logger.debug('Resolving %s', domain)

        try:
            params = {
                'type': qtype,
                'ct': 'application/dns-message'
            }
            query_message = dns.message.make_query(domain, qtype)
            query_wire = query_message.to_wire()
            query_b64 = base64.urlsafe_b64encode(query_wire).decode('utf-8').rstrip('=')
            query_url = f'{self.dns_url}?dns={query_b64}'

            async with self.session.get(
                query_url, params=params, headers=self.header
            ) as resp:
                content_type = resp.headers.get('content-type')
                if (
                    resp.status == 200 and content_type == 'application/dns-message'
                ):
                    resp_wire = await resp.read()
                    resp_message = dns.message.from_wire(resp_wire)

                    for answer in resp_message.answer:
                        if answer.rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
                            result = answer[0].address
                            logger.debug('Resolved %s to %s', domain, result)
                            return result
                else:
                    logger.error(
                        'Invalid DoH response for %s | Status: %s, Reason: %s',
                        domain, resp.status, resp.reason
                    )
                    return None

        except Exception as e:
            logger.error('While resolving %s: %s', domain, repr(e))
            return None
