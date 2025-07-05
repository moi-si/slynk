import socket
import asyncio
import ipaddress
import copy

from .logger_with_context import logger, domain_policy
from . import utils
from .config import (
    domain_policies,
    CONFIG,
    default_policy,
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

def redirect(ip):
    if ':' in ip:
        mapped_ip = ipv6_map.search(utils.ip_to_binary_prefix(ip))
    else:
        mapped_ip = ipv4_map.search(utils.ip_to_binary_prefix(ip))
    if mapped_ip is None:
        return ip
    if ip == mapped_ip:
        return mapped_ip
    logger.info("Redirect %s to %s", ip, mapped_ip)
    if mapped_ip[0] == "^":
        return mapped_ip[1:]
    return redirect(mapped_ip)

def match_domain(domain):
    matched_domains = domain_policies.search(f'^{domain}$')
    if matched_domains:
        return copy.deepcopy(
            CONFIG["domains"].get(sorted(matched_domains, key=len, reverse=True)[0])
        )
    else:
        return {}

async def get_connection(host, port, dns_resolver, protocol=6):
    policy = {**default_policy, **match_domain(host)}
    domain_policy.set(policy)
    policy.setdefault('port', 443)
    port = policy['port']
    if utils.is_ip_address(host):
        ip = host
    elif policy.get('IP'):
        ip = policy['IP']
    elif DNS_cache.get(host):
        ip = DNS_cache[host]
        logger.info('DNS cache for %s is %s.', host, ip)
    else:
        if policy.get('IPv6_first'):
            try:
                ip = await dns_resolver.resolve(host, 'AAAA')
            except Exception:
                logger.warning('Failed to resolve %s via IPv6. Trying IPv4.')
                ip = await dns_resolver.resolve(host, 'A')
        else:
            try:
                ip = await dns_resolver.resolve(host, 'A')
            except Exception:
                logger.warning('Failed to resolve %s via IPv4. Trying IPv6.')
                ip = await dns_resolver.resolve(host, 'AAAA')
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
    ip = redirect(ip)

    if policy.get('fake_ttl') == 'query' and policy["mode"] == "FAKEdesync":
        logger.info('Fake TTL for %s is query.', ip)
        if TTL_cache.get(ip):
            policy["fake_ttl"] = TTL_cache[ip] - 1
            logger.info("TTL cache for %s is %d.", ip, policy['fake_ttl'])
        else:
            val = await utils.to_thread(utils.get_ttl, ip, port)
            if val == -1:
                raise RuntimeError(f'Failed to get TTL for {ip}:{port}.')
            global cnt_upd_TTL_cache
            async with lock_TTL_cache:
                TTL_cache[ip] = val
                cnt_upd_TTL_cache += 1
                if cnt_upd_TTL_cache >= CONFIG["TTL_cache_update_interval"]:
                    cnt_upd_TTL_cache = 0
                    await utils.to_thread(write_TTL_cache)
            policy["fake_ttl"] = val - 1
            logger.info('TTL cache for %s to %d.', ip, policy["fake_ttl"])

    logger.info('%s --> %s', host, policy)
    if protocol == 6:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=30
        )
        return reader, writer
    elif protocol == 17:
        raise NotImplementedError('UDP is not supported yet.')
    else:
        raise ValueError(f'Unknown protocol: {protocol}')
