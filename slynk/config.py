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
    default_policy['fake_packet'] = fake_packet.encode(encoding='UTF-8')

if (match_mode := CONFIG.get('match_mode')) == 'ac':
    import copy
    import ahocorasick  # pip install ahocorasick-python
    domain_policies = ahocorasick.AhoCorasick(
        *CONFIG['domain_policies'].keys()
    )

    def match_domain(domain):
        matched_domains = domain_policies.search(f'^{domain}$')
        if matched_domains:
            return copy.deepcopy(
                CONFIG['domain_policies'].get(
                    sorted(matched_domains, key=len, reverse=True)[0]
                )
            )
        else:
            return {}

elif match_mode == 'trie':
    from . import trie_matcher
    matcher = trie_matcher.TrieMatcher()

    def _expand_pattern(s):
        parts = []
        current = []
        in_brackets = False
        
        for char in s:
            if char == '(' and not in_brackets:
                if current:
                    parts.append(''.join(current))
                    current = []
                in_brackets = True
            elif char == ')' and in_brackets:
                options = ''.join(current).split('/')
                parts.append(options)
                current = []
                in_brackets = False
            else:
                current.append(char)

        if current:
            parts.append(''.join(current))

        result = ['']
        for part in parts:
            if isinstance(part, str):
                result = [s + part for s in result]
            else:
                new_result = []
                for s1 in result:
                    for s2 in part:
                        new_result.append(s1 + s2)
                result = new_result
        return result

    expanded_policies = {}
    for key in CONFIG['domain_policies'].keys():
        for item in key.replace(' ', '').split(','):
            for pattern in _expand_pattern(item):
                expanded_policies[pattern] = CONFIG['domain_policies'][key]
                matcher.add_pattern(pattern)
    CONFIG['domain_policies'] = expanded_policies

    def match_domain(domain):
        if pattern := matcher.match(domain):
            return CONFIG['domain_policies'][pattern]
        else:
            return {}

else:
    raise ValueError('Unknown domain matching mode')


class TrieNode:
    def __init__(self):
        self.children = [None, None]
        self.val = None


class Trie:
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

try:
    with open("DNS_cache.json", "rb") as f:
        DNS_cache = json.load(f)
except FileNotFoundError:
    print('DNS cache not found')

try:
    with open("TTL_cache.json", "rb") as f:
        TTL_cache = json.load(f)
except FileNotFoundError:
    print('TTL cache not found')

def write_DNS_cache():
    with open("DNS_cache.json", "w") as f:
        json.dump(DNS_cache, f)

def write_TTL_cache():
    with open("TTL_cache.json", "w") as f:
        json.dump(TTL_cache, f)
