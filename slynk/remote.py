import socket
import asyncio
import ipaddress
import time

from .logger_with_context import logger, policy_ctx
from . import utils
from .config import (
    default_policy,
    match_domain,
    match_ip,
    CONFIG,
    DNS_cache,
    TTL_cache,
    write_DNS_cache,
    write_TTL_cache
)

logger = logger.getChild('remote')

cnt_upd_TTL_cache = 0
lock_TTL_cache = asyncio.Lock()
cnt_upd_DNS_cache = 0
lock_DNS_cache = asyncio.Lock()

def ip_redirect(ip: str) -> str:
    if (mapped_ip := match_ip(ip).get('map_to')) is None:
        return ip
    chained = True
    if mapped_ip[0] == '^':
        mapped_ip = mapped_ip[1:]
        chained = False
    if '/' in mapped_ip:
        mapped_ip = utils.transform_ip(ip, mapped_ip)
    if ip == mapped_ip:
        return ip
    logger.debug("Redirect %s to %s", ip, mapped_ip)
    return ip_redirect(mapped_ip) if chained else mapped_ip

async def get_connection(host, port, dns_query, protocol=6):
    domain_policy = match_domain(host)
    policy = {**default_policy, **domain_policy}
    old_port, port = port, policy.setdefault('port', port)

    if policy.get('IP'):
        ip = policy['IP']
    elif utils.is_ip_address(host):
        ip = host
    elif DNS_cache.get(host):
        ip = DNS_cache[host][0]
        logger.debug('DNS cache for %s is %s.', host, ip)
    else:
        if policy.get('IPv6_first'):
            try:
                ip = await dns_query(host, 'AAAA')
            except Exception:
                logger.warning(
                    'Failed to resolve %s via IPv6. Trying IPv4.', host
                )
                ip = await dns_query(host, 'A')
        else:
            try:
                ip = await dns_query(host, 'A')
            except Exception:
                logger.warning(
                    'Failed to resolve %s via IPv4. Trying IPv6.', host
                )
                ip = await dns_query(host, 'AAAA')
        if ip is None:
            raise RuntimeError(f'Failed to resolve {host}.')
        elif policy.get('DNS_cache'):
            global cnt_upd_DNS_cache
            async with lock_DNS_cache:
                if ttl := policy.get('DNS_cache_TTL'):
                    expries = time.time() + ttl
                else:
                    expries = None
                DNS_cache[host] = (ip, expries)
                cnt_upd_DNS_cache += 1
                if cnt_upd_DNS_cache >= CONFIG["DNS_cache_update_interval"]:
                    cnt_upd_DNS_cache = 0
                    await utils.to_thread(write_DNS_cache)
            logger.debug('DNS cache for %s to %s.', host, ip)

    if host != ip:
        ip = ip_redirect(ip)
    policy = {**default_policy, **match_ip(ip), **domain_policy}

    if policy["mode"] == "FAKEdesync" and policy['fake_ttl'][0] == 'q':
        logger.debug('TTL rule for %s is %s.', ip, policy['fake_ttl'])
        if TTL_cache.get(ip):
            val = TTL_cache[ip]
            logger.debug("TTL cache for %s is %s.", ip, val)
        else:
            val = await utils.to_thread(utils.get_ttl, ip, port)
            if val == -1:
                raise RuntimeError(f'Failed to get TTL for {ip}:{port}.')
            if policy.get('TTL_cache'):
                global cnt_upd_TTL_cache
                async with lock_TTL_cache:
                    TTL_cache[ip] = val
                    cnt_upd_TTL_cache += 1
                    if cnt_upd_TTL_cache >= CONFIG[
                        "TTL_cache_update_interval"
                    ]:
                        cnt_upd_TTL_cache = 0
                        await utils.to_thread(write_TTL_cache)
                logger.debug('TTL cache for %s to %d.', ip, val)
        policy['fake_ttl'] = utils.calc_ttl(policy['fake_ttl'], val)
        logger.debug('Fake TTL for %s is %d.', ip, policy['fake_ttl'])

    policy_ctx.set(policy)
    logger.debug('%s -> %s', host, policy)

    if protocol == 6:  # TCP
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=policy.get('TCP_timeout') or 15
            )
            return reader, writer
        except Exception as e:
            logger.error(
                'Failed to connect to %s:%d(%s:%d) due to %s.',
                host, old_port, ip, port, repr(e)
            )
            return None
    elif protocol == 17:
        raise NotImplementedError('UDP is not supported yet.')
    else:
        raise ValueError(f'Unknown protocol: {protocol}')
