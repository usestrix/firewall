use super::Registry;

/// No patterns yet, so go fetches are aliased but not screened.
pub static GO: Registry = Registry {
    prefix: "/go/",
    eco: "go",
    osv: "Go",
    upstream: "https://proxy.golang.org/",
    index: true,
    patterns: &[],
};
