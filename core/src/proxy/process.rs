use std::process::Command;

/// Names the process that owns the client's source port.
pub fn lookup(port: u16) -> (String, String) {
    if port == 0 {
        return ("unknown".into(), String::new());
    }
    let out = match Command::new("lsof")
        .args(["-nP", "+c", "0", &format!("-iTCP:{port}"), "-sTCP:ESTABLISHED"])
        .output()
    {
        Ok(o) => o,
        Err(_) => return ("unknown".into(), String::new()),
    };
    let text = String::from_utf8_lossy(&out.stdout);
    let want = format!("127.0.0.1:{port}->");
    for line in text.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        // lsof's NAME column is local->remote; match the local end.
        if f.len() >= 9 && f[8].starts_with(&want) {
            let pid = f[1];
            let args = Command::new("ps")
                .args(["-p", pid, "-o", "args="])
                .output()
                .ok()
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                .unwrap_or_default();
            return (format!("{} (pid {pid})", f[0]), args);
        }
    }
    ("unknown".into(), String::new())
}
