import asyncio
import json
from pathlib import Path
import shutil
import random
import time
import argparse

from . import trie_utils
from .utils import ip_to_binary_prefix, get_lan_ip, expand_pattern

basepath = Path(__file__).parent.parent

if Path('config.json').exists():
    config_path = 'config.json'
else:
    config_path = basepath / 'config.json'
with open(config_path, "rb") as f:
    CONFIG = json.load(f)

default_policy = CONFIG['default_policy']
fake_packet = default_policy.get('fake_packet')
default_policy['fake_packet'] = fake_packet.encode(encoding='iso-8859-1')

if default_policy["fake_ttl"] == "auto":
    # Temp code for auto fake_ttl
    default_policy["fake_ttl"] = random.randint(10, 60)

if (match_mode := CONFIG.get('match_mode')) == 'ac':
    import copy
    import ahocorasick  # pip install ahocorasick-python

    expanded_policies = {}
    for key in CONFIG['domain_policies'].keys():
        for pattern in expand_pattern(key):
            expanded_policies[pattern] = CONFIG['domain_policies'][key]
    CONFIG['domain_policies'] = expanded_policies
    matcher = ahocorasick.AhoCorasick(
        *CONFIG['domain_policies'].keys()
    )

    def match_domain(host):
        if matched_domains := matcher.search(f'^{host}$'):
            return copy.deepcopy(
                CONFIG['domain_policies'].get(
                    sorted(matched_domains, key=len, reverse=True)[0]
                )
            )
        else:
            return {}

elif match_mode == 'trie':
    matcher = trie_utils.DomainMatcher()
    expanded_policies = {}
    for key in CONFIG['domain_policies'].keys():
        for item in key.replace(' ', '').split(','):
            for pattern in expand_pattern(item):
                expanded_policies[pattern] = CONFIG['domain_policies'][key]
                matcher.add_pattern(pattern)
    CONFIG['domain_policies'] = expanded_policies

    def match_domain(host: str) -> dict:
        if pattern := matcher.match(host):
            return CONFIG['domain_policies'][pattern]
        else:
            return {}

else:
    raise ValueError(f'Unknown domain matching mode: {match_mode}')

expanded_policies = {}
for key in CONFIG['ip_policies']:
    for ip_or_network in key.replace(' ', '').split(','):
        expanded_policies[ip_or_network] = CONFIG['ip_policies'][key]
ipv4_map, ipv6_map = trie_utils.Trie(), trie_utils.Trie()
CONFIG['ip_policies'] = expanded_policies

for k, v in CONFIG['ip_policies'].items():
    if ':' in k:
        ipv6_map.insert(ip_to_binary_prefix(k), v)
    else:
        ipv4_map.insert(ip_to_binary_prefix(k), v)

def match_ip(ip: str) -> dict:
    if ':' in ip:
        return ipv6_map.search(ip_to_binary_prefix(ip))
    else:
        return ipv4_map.search(ip_to_binary_prefix(ip))

TTL_cache = {}  # TTL for each IP
old_TTL_cache = {}
DNS_cache = {}  # DNS cache for each domain
old_DNS_cache = {}

def init_cache():
    global old_DNS_cache
    try:
        with open("DNS_cache.json", "rb") as f:
            DNS_cache.update(json.load(f))
        t = time.time()
        old_DNS_cache = DNS_cache.copy()
        for domain, value in old_DNS_cache.items():
            expries = value[1]
            if expries and expries <= t:
                DNS_cache.pop(domain)
    except Exception as e:
        print(f'DNS_cache.json: {repr(e)}')

    global old_TTL_cache
    try:
        with open("TTL_cache.json", "rb") as f:
            TTL_cache.update(json.load(f))
        old_TTL_cache = TTL_cache.copy()
    except Exception as e:
        print(f'TTL_cache.json: {repr(e)}')

def write_DNS_cache():
    with open("DNS_cache.json", "w") as f:
        json.dump(DNS_cache, f)

def write_TTL_cache():
    with open("TTL_cache.json", "w") as f:
        json.dump(TTL_cache, f)

def save_cache():
    if old_DNS_cache != DNS_cache:
        write_DNS_cache()
        print('DNS cache saved.')
    if old_TTL_cache != TTL_cache:
        write_TTL_cache()
        print('TTL cache saved.')

def parse_args():
    parser = argparse.ArgumentParser(
        description='Command-line options for slynk '
        '(override config.json settings).')
    parser.add_argument(
        '--host', type=str, metavar='host',default=None, help='Server host')
    parser.add_argument(
        '--port', type=int, metavar='port',default=None, help='Server port')
    parser.add_argument(
        '--protocol', type=str, metavar='protocol', default=None,
        help='Proxy protocol (HTTP or SOCKS5)')
    args = parser.parse_args()
    CONFIG['server_host'] = args.host or CONFIG.get('server_host') or '127.0.0.1'
    CONFIG['server_port'] = args.port or CONFIG.get('server_port') or 3500
    CONFIG['proxy_protocol'] = args.protocol or CONFIG.get('proxy_protocol')
