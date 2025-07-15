import asyncio
import json
from pathlib import Path
import shutil
import ipaddress
import random

from .utils import ip_to_binary_prefix

basepath = Path(__file__).parent.parent

CONFIG = {}
if not Path("config.json").exists():
    shutil.copyfile(basepath / "config.json", "config.json")
with open("config.json", "rb") as f:
    _CONFIG = json.load(f)

CONFIG = {**_CONFIG, **CONFIG}
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
    from . import trie_matcher
    matcher = trie_matcher.TrieMatcher()

    def expand_pattern(s):
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
        return [prefix + part + suffix for part in inner.split('/')]

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


class TrieNode:
    __slots__ = ('children', 'val')
    def __init__(self):
        self.children = [None, None]
        self.val = None


class Trie:
    __slots__ = ('root',)
    def __init__(self):
        self.root = TrieNode()

    def insert(self, prefix, value):
        node = self.root
        for bit in prefix:
            index = int(bit)
            if not node.children[index]:
                node.children[index] = TrieNode()
            node = node.children[index]
        node.val = value

    def search(self, prefix):
        node = self.root
        ans = None
        for bit in prefix:
            index = int(bit)
            if node.val is not None:
                ans = node.val
            if not node.children[index]:
                return ans
            node = node.children[index]
        if node.val is not None:
            ans = node.val
        return ans


ipv4_map = Trie()
ipv6_map = Trie()

for k, v in CONFIG["IPredirect"].items():
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
