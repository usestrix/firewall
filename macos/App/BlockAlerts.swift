import AppKit

struct BlockedPackage: Codable, Hashable, Identifiable {
    let eco: String
    let name: String
    let version: String?
    let filter: String
    let reason: String

    var id: String { "\(eco)/\(name)@\(version ?? "")" }
    var label: String { version.map { "\(name) \($0)" } ?? name }
    /// The denylist and OSV only flag packages known to be malicious; the age check only holds back new ones.
    var malicious: Bool { filter != "age" }
}

@MainActor
enum BlockAlert {
    static func show(_ package: BlockedPackage) {
        let alert = NSAlert()
        alert.addButton(withTitle: "OK")
        if package.malicious {
            alert.alertStyle = .critical
            alert.messageText = "Blocked a malicious package"
            alert.informativeText = "\(package.label) (\(package.eco)) \(package.reason). Do not install it."
        } else {
            alert.messageText = "Held back a new package"
            alert.informativeText = "\(package.label) (\(package.eco)) \(package.reason)."
        }
        NSApp.activate(ignoringOtherApps: true)
        alert.runModal()
    }
}
