import base64
import asyncio
import aiohttp
import dns.message
import dns.rdatatype

from .logger_with_context import logger
logger = logger.getChild('dns_resolver')

async def resolve(domain, qtype, dns_url, proxy=None):
    logger.info('DNS Resolving %s', domain)

    try:
        params = {
            'type': qtype,
            'ct': 'application/dns-message'
        }
        headers = {'Accept': 'application/dns-message'}
        query_message = dns.message.make_query(domain, qtype)
        query_wire = query_message.to_wire()
        query_b64 = base64.urlsafe_b64encode(query_wire).decode('utf-8').rstrip('=')
        query_url = f'{dns_url}?dns={query_b64}'

        async with aiohttp.ClientSession() as session:
            async with session.get(
                query_url, params=params, headers=headers, proxy=proxy
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
