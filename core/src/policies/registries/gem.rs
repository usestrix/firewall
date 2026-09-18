use super::Registry;

/// No patterns yet, so gem fetches are aliased but not screened.
pub static GEM: Registry = Registry {
    prefix: "/gem/",
    eco: "gem",
    osv_name: "RubyGems",
    upstream: "https://rubygems.org/",
    index: true,
    patterns: &[],
};
