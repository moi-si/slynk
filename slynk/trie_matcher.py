class TrieMatcher:
    class TrieNode:
        __slots__ = ('children', 'wildcard_subdomain', 'wildcard_full')

        def __init__(self):
            self.children = {}
            self.wildcard_subdomain = None
            self.wildcard_full = None

    __slots__ = ('exact_domains', 'trie_root')

    def __init__(self):
        self.exact_domains = set()
        self.trie_root = self.TrieNode()
    
    def add_pattern(self, pattern: str):
        if not pattern or '.' not in pattern:
            raise ValueError(f'Invaild pattern: {pattern}')
        elif pattern.startswith('*.'):
            domain = pattern[2:]
            if not (parts := domain.split('.')):
                return
            parts.reverse()
            self._add_to_trie(parts, pattern, 1)
        elif pattern.startswith('*'):
            domain = pattern[1:]
            if not (parts := domain.split('.')):
                return
            parts.reverse()
            self._add_to_trie(parts, pattern, 2)
        elif '*' not in pattern:
            self.exact_domains.add(pattern)
        else:
            raise ValueError('Invaild pattern: {pattern}')
    
    def _add_to_trie(self, parts, pattern, pattern_type):
        node = self.trie_root
        for part in parts:
            if part not in node.children:
                node.children[part] = self.TrieNode()
            node = node.children[part]
        if pattern_type == 1:
            node.wildcard_subdomain = pattern
        elif pattern_type == 2:
            node.wildcard_full = pattern
    
    def match(self, domain: str):
        if not domain:
            return None

        if domain in self.exact_domains:
            return domain

        parts = domain.split('.')
        parts.reverse()
        n = len(parts)

        best_pattern_subdomain = best_pattern_full = None
        best_depth_subdomain = best_depth_full = -1
        
        node = self.trie_root
        for i, part in enumerate(parts):
            if part not in node.children:
                break
            node = node.children[part]
            depth = i + 1

            if node.wildcard_subdomain is not None and i < n - 1 and depth > best_depth_subdomain:
                best_depth_subdomain = depth
                best_pattern_subdomain = node.wildcard_subdomain

            if node.wildcard_full is not None and depth > best_depth_full:
                best_depth_full = depth
                best_pattern_full = node.wildcard_full

        if best_depth_subdomain != -1:
            return best_pattern_subdomain
        elif best_depth_full != -1:
            return best_pattern_full
        return None
