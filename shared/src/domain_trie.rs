use std::collections::HashMap;

#[derive(Debug, Clone, Default, PartialEq)]
pub enum DomainTriePolicy {
    #[default]
    None,
    Drop,
    Redirect(Vec<String>),
}

#[derive(Default)]
pub struct DomainTrie {
    children: HashMap<String, DomainTrie>,
    policy: DomainTriePolicy,
}

impl DomainTrie {
    pub fn new() -> Self {
        Self::default()
    }

    /// Walks/creates the path for `pattern` and sets the policy on the
    /// resulting leaf node - NOT on `self`. This is the fix for the bug
    /// in the draft: `node` (the leaf found by the loop) must be the
    /// thing mutated, since `self` is still the trie root at this point.
    fn insert_with_policy(&mut self, pattern: &str, policy: DomainTriePolicy) {
        let pattern = pattern.trim_end_matches('.').to_lowercase();
        let pattern = pattern.strip_prefix("*.").unwrap_or(&pattern);

        let mut node = self;
        for label in pattern.rsplit('.') {
            node = node.children.entry(label.to_string()).or_default();
        }
        node.policy = policy;
    }

    pub fn insert_drop(&mut self, pattern: &str) {
        self.insert_with_policy(pattern, DomainTriePolicy::Drop);
    }

    /// `ip_with_port` matches your existing redirect_list's second tuple
    /// element, e.g. "10.0.0.5,10.0.0.6" or "10.0.0.5:53" - split on both
    /// separators the same way your old craft_redirect_response call site did.
    pub fn insert_redirect(&mut self, pattern: &str, ip_with_port: &str) {
        let ips: Vec<String> = ip_with_port
            .split(',')
            .map(|entry| entry.split(':').next().unwrap_or(entry).to_string())
            .collect();
        self.insert_with_policy(pattern, DomainTriePolicy::Redirect(ips));
    }

    pub fn build(drop_list: &[String], redirect_list: &[(String, String)]) -> Self {
        let mut trie = Self::new();

        let is_file_reference = |pattern: &str| {
            pattern.starts_with('/') || pattern.starts_with("./") || pattern.starts_with("../")
        };

        let read_list_file = |path: &str| -> Vec<String> {
            match std::fs::read_to_string(path) {
                Ok(content) => content
                    .lines()
                    .filter_map(|raw_line| {
                        let line = raw_line.trim();
                        if line.is_empty() || line.starts_with('#') {
                            return None;
                        }
                        line.split_whitespace().next().map(str::to_string)
                    })
                    .collect(),
                Err(err) => {
                    tracing::error!("failed to read list file {}: {}", path, err);
                    Vec::new()
                }
            }
        };

        for entry in drop_list {
            let pattern = entry.trim();
            if pattern.is_empty() || pattern.starts_with('#') {
                continue;
            }
            if is_file_reference(pattern) {
                let lines = read_list_file(pattern);
                tracing::info!("loaded {} drop entries from {}", lines.len(), pattern);
                for domain in &lines {
                    trie.insert_drop(domain);
                }
            } else {
                trie.insert_drop(pattern);
            }
        }

        for (pattern, target) in redirect_list {
            let pattern = pattern.trim();
            if pattern.is_empty() || pattern.starts_with('#') {
                continue;
            }
            if is_file_reference(pattern) {
                let lines = read_list_file(pattern);
                tracing::info!("loaded {} redirect entries from {}", lines.len(), pattern);
                for line in &lines {
                    match line.split_once(':') {
                        Some((from, to)) if !from.trim().is_empty() && !to.trim().is_empty() => {
                            trie.insert_redirect(from.trim(), to.trim());
                        }
                        _ => tracing::warn!(
                            "skipping malformed redirect line in {}: {:?} (expected domain:ip1,ip2)",
                            pattern,
                            line
                        ),
                    }
                }
            } else {
                trie.insert_redirect(pattern, target);
            }
        }

        trie
    }

    /// Returns the policy at the closest matching boundary, walking TLD-down.
    /// A non-`None` policy on an ancestor short-circuits the walk, matching
    /// "*.example.com blocks all subdomains" semantics.
    pub fn lookup(&self, domain: &str) -> &DomainTriePolicy {
        let domain = domain.trim_end_matches('.').to_lowercase();
        let mut node = self;
        for label in domain.rsplit('.') {
            match node.children.get(label) {
                Some(next) => {
                    if next.policy != DomainTriePolicy::None {
                        return &next.policy;
                    }
                    node = next;
                }
                None => return &DomainTriePolicy::None,
            }
        }
        &DomainTriePolicy::None
    }
}
pub enum RuleMatch {
    Drop,
    Redirect(Vec<String>),
    None,
}

pub fn check_rules(domain: &str, trie: &DomainTrie) -> RuleMatch {
    match trie.lookup(domain) {
        DomainTriePolicy::Drop => RuleMatch::Drop,
        DomainTriePolicy::Redirect(ips) => RuleMatch::Redirect(ips.clone()),
        DomainTriePolicy::None => RuleMatch::None,
    }
}
