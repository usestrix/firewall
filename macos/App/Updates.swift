import AppKit

enum Updates {
    static let current = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? ""

    private struct Release: Decodable {
        let tag_name: String
    }

    /// The latest release's version, when it is newer than this app.
    static func available() async -> String? {
        let latest = URL(string: "https://api.github.com/repos/usestrix/firewall/releases/latest")!
        guard let (data, _) = try? await URLSession.shared.data(from: latest),
              let release = try? JSONDecoder().decode(Release.self, from: data) else { return nil }
        let version = release.tag_name.hasPrefix("v") ? String(release.tag_name.dropFirst()) : release.tag_name
        return version.compare(current, options: .numeric) == .orderedDescending ? version : nil
    }

    static func download(_ version: String) {
        NSWorkspace.shared.open(URL(string: "https://github.com/usestrix/firewall/releases/download/v\(version)/Firewall.pkg")!)
    }

    @MainActor static func prompt(_ version: String) {
        let alert = NSAlert()
        alert.messageText = "Firewall \(version) is available"
        alert.informativeText = "You have \(current). Download the installer and open it to update."
        alert.addButton(withTitle: "Download")
        alert.addButton(withTitle: "Later")
        NSApp.activate(ignoringOtherApps: true)
        if alert.runModal() == .alertFirstButtonReturn { download(version) }
    }
}
