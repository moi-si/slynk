import asyncio
import json
from pathlib import Path
import shutil
import random

from . import trie_utils
from .utils import ip_to_binary_prefix

basepath = Path(__file__).parent.parent

if Path('config.json').exists():
    config_path = 'config.json'
else:
    config_path = basepath / 'config.json'
with open(config_path, "rb") as f:
    CONFIG = json.load(f)

default_policy = CONFIG['default_policy']
fake_packet = default_policy.get('fake_packet')
if fake_packet:
    default_policy['fake_packet'] = fake_packet.encode(encoding='iso-8859-1')

if (match_mode := CONFIG.get('match_mode')) == 'ac':
    import copy
    import ahocorasick  # pip install ahocorasick-python
    domain_policies = ahocorasick.AhoCorasick(
        *CONFIG['domain_policies'].keys()
    )

    def get_policy(host):
        if matched_domains := domain_policies.search(f'^{host}$'):
            return {
                **default_policy,
                **copy.deepcopy(
                    CONFIG['domain_policies'].get(
                        sorted(matched_domains, key=len, reverse=True)[0]
                    )
                )
            }
        else:
            return default_policy

elif match_mode == 'trie':
    matcher = trie_utils.DomainMatcher()

    def expand_pattern(s: str) -> list | tuple:
        left_index, right_index = s.find('('), s.find(')')
        if left_index == -1 and right_index == -1:
            return s.split('/')
        if -1 in (left_index, right_index):
            raise ValueError("Both '(' and ')' must be present", s)
        if left_index > right_index:
            raise ValueError("'(' must occur before ')'", s)
        if right_index == left_index + 1:
            raise ValueError(
                'A vaild string should exist between a pair of parentheses', s
            )
        prefix = s[:left_index]
        suffix = s[right_index + 1:]
        inner = s[left_index + 1:right_index]
        return (prefix + part + suffix for part in inner.split('/'))

    expanded_policies = {}
    for key in CONFIG['domain_policies'].keys():
        for item in key.replace(' ', '').split(','):
            for pattern in expand_pattern(item):
                expanded_policies[pattern] = CONFIG['domain_policies'][key]
                matcher.add_pattern(pattern)
    CONFIG['domain_policies'] = expanded_policies

    def get_policy(host):
        if pattern := matcher.match(host):
            return {**default_policy, **CONFIG['domain_policies'][pattern]}
        else:
            return default_policy

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

if default_policy["fake_ttl"] == "auto":
    # Temp code for auto fake_ttl
    default_policy["fake_ttl"] = random.randint(10, 60)

TTL_cache = {}  # TTL for each IP
DNS_cache = {}  # DNS cache for each domain

def init_cache():
    try:
        with open("DNS_cache.json", "rb") as f:
            DNS_cache = json.load(f)
    except Exception as e:
        print(f'DNS_cache.json: {repr(e)}')

    try:
        with open("TTL_cache.json", "rb") as f:
            TTL_cache = json.load(f)
    except Exception as e:
        print(f'TTL_cache.json: {repr(e)}')

def write_DNS_cache():
    with open("DNS_cache.json", "w") as f:
        json.dump(DNS_cache, f)

def write_TTL_cache():
    with open("TTL_cache.json", "w") as f:
        json.dump(TTL_cache, f)
