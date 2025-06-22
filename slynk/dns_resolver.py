import base64
import asyncio
import aiohttp
import dns.message
import dns.rdatatype

from .logger_with_context import logger
logger = logger.getChild('dns_resolver')


class Resolver:
    def __init__(self, dns_url, proxy=None):
        self.dns_url = dns_url
        self.proxy = proxy
        self.session = None
        self.headers = {'Accept': 'application/dns-message'}

    async def create_session(self):
        self.session = aiohttp.ClientSession()

    async def close_session(self):
        if self.session:
            await self.session.close()
            self.session = None

    async def resolve(self, domain, qtype):
        logger.info('DNS Resolving %s', domain)

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
                query_url, params=params, headers=self.headers, proxy=self.proxy
            ) as resp:
                if resp.status == 200 and resp.headers.get('content-type') == 'application/dns-message':
                    resp_wire = await resp.read()
                    resp_message = dns.message.from_wire(resp_wire)

                    for answer in resp_message.answer:
                        if answer.rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
                            result = answer[0].address
                            logger.info('Resolved %s to %s', domain, result)
                            return result
                else:
                    logger.error(
                        'Invalid DoH response | Status: %s, Reason: %s', resp.status, resp.reason
                    )
                    return None

        except Exception as e:
            logger.error('%s while resolving %s', repr(e), domain)
            return None
