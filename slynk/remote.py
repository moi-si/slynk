import socket
import asyncio
import ipaddress

from .logger_with_context import logger, domain_policy
from . import utils
from .config import (
    get_policy,
    CONFIG,
    ipv4_map,
    ipv6_map,
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
    if ':' in ip:
        ip_policy = ipv6_map.search(utils.ip_to_binary_prefix(ip))
    else:
        ip_policy = ipv4_map.search(utils.ip_to_binary_prefix(ip))
    if ip_policy is None or (mapped_ip := ip_policy.get('map_to')) is None:
        return ip
    chained = True
    if mapped_ip[0] == '^':
        mapped_ip = mapped_ip[1:]
        chained = False
    if '/' in mapped_ip:
        mapped_ip = utils.transform_ip(ip, mapped_ip)
    if ip == mapped_ip:
        return ip
    logger.info("Redirect %s to %s", ip, mapped_ip)
    return ip_redirect(mapped_ip) if chained else mapped_ip

async def get_connection(host, port, dns_query, protocol=6):
    policy = get_policy(host)
    old_port, port = port, policy.setdefault('port', 443)
    if policy.get('IP'):
        ip = policy['IP']
    elif utils.is_ip_address(host):
        ip = host
    elif DNS_cache.get(host):
        ip = DNS_cache[host]
        logger.info('DNS cache for %s is %s.', host, ip)
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
                DNS_cache[host] = ip
                cnt_upd_DNS_cache += 1
                if cnt_upd_DNS_cache >= CONFIG["DNS_cache_update_interval"]:
                    cnt_upd_DNS_cache = 0
                    await utils.to_thread(write_DNS_cache)
            logger.info('DNS cache for %s to %s.', host, ip)

    ip = ip_redirect(ip)
    if ':' in ip:
        ip_policy = ipv6_map.search(utils.ip_to_binary_prefix(ip))
    else:
        ip_policy = ipv4_map.search(utils.ip_to_binary_prefix(ip))
    if ip_policy is not None:
        policy = {**policy, **ip_policy}

    if policy.get('fake_ttl') == 'query' and policy["mode"] == "FAKEdesync":
        logger.info('Fake TTL for %s is query.', ip)
        if TTL_cache.get(ip):
            policy["fake_ttl"] = TTL_cache[ip] - 1
            logger.info("TTL cache for %s is %d.", ip, policy['fake_ttl'])
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
            policy["fake_ttl"] = val - 1
            logger.info('TTL cache for %s to %d.', ip, policy["fake_ttl"])

    domain_policy.set(policy)
    logger.info('%s --> %s', host, policy)

    if protocol == 6:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=15
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
