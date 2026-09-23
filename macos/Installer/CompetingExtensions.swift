import AppKit

/// Self-contained: removing this file and its one call in `InstallerModel.install()` removes the feature.
enum CompetingExtensions {
    /// Warns about other active network extensions; false if the user cancels.
    static func confirmInstall() -> Bool {
        let competing = find()
        guard !competing.isEmpty else { return true }
        let alert = NSAlert()
        alert.alertStyle = .warning
        alert.messageText = "Other network extensions are installed"
        alert.informativeText = """
            Firewall may not screen downloads reliably while these are active:

            \(competing.map { "• \($0)" }.joined(separator: "\n"))
            """
        alert.addButton(withTitle: "Install Anyway")
        alert.addButton(withTitle: "Cancel")
        NSApp.activate(ignoringOtherApps: true)
        return alert.runModal() == .alertFirstButtonReturn
    }

    /// No public API lists other vendors' extensions, so this reads sysextd's undocumented db.plist, as osquery's
    /// `system_extensions` table does (github.com/osquery/osquery/pull/6863). If the format changes, there is no warning.
    private static func find() -> [String] {
        guard let db = NSDictionary(contentsOfFile: "/Library/SystemExtensions/db.plist"),
              let extensions = db["extensions"] as? [[String: Any]]
        else { return [] }

        var found: [String] = []
        for entry in extensions {
            guard entry["state"] as? String == "activated_enabled",
                  (entry["categories"] as? [String])?.contains("com.apple.system_extension.network_extension") == true,
                  let identifier = entry["identifier"] as? String,
                  identifier != FirewallIDs.extensionBundleID
            else { continue }

            let container = (entry["container"] as? [String: Any])?["bundlePath"] as? String
            let app = container.map { FileManager.default.displayName(atPath: $0) } ?? identifier
            let bundle = (entry["stagedBundleURL"] as? [String: Any])?["relative"] as? String
            let info = bundle.flatMap(URL.init(string:)).flatMap {
                NSDictionary(contentsOf: $0.appendingPathComponent("Contents/Info.plist"))
            }
            let providers = (info?["NetworkExtension"] as? [String: Any])?["NEProviderClasses"] as? [String: Any]
            let kinds = (providers?.keys.sorted() ?? []).map { kindNames[$0] ?? $0 }

            let summary = kinds.isEmpty ? app : "\(app) (\(kinds.joined(separator: ", ")))"
            if !found.contains(summary) { found.append(summary) }
        }
        return found
    }

    private static let kindNames = [
        "com.apple.networkextension.app-proxy": "transparent proxy",
        "com.apple.networkextension.packet-tunnel": "VPN",
        "com.apple.networkextension.filter-data": "content filter",
        "com.apple.networkextension.filter-packet": "packet filter",
        "com.apple.networkextension.dns-proxy": "DNS proxy",
    ]
}
