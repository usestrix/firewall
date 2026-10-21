import AppKit
import Security

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
    /// Malware is never allowed, and a new package only by version.
    var trustable: Bool { !malicious && version != nil }
}

@MainActor
enum BlockAlert {
    /// Returns whether the user chose to trust the package.
    static func show(_ package: BlockedPackage) -> Bool {
        let alert = NSAlert()
        alert.addButton(withTitle: "OK")
        if package.malicious {
            alert.alertStyle = .critical
            alert.messageText = "Blocked malware: \(package.label) (\(package.eco))"
            alert.informativeText = "\(package.label) \(package.reason).\n\n"
                + "It was not installed. Don't install it from another source. "
                + "If you didn't expect this package, a dependency may be compromised; tell your security team."
        } else {
            alert.messageText = "Held back a new package"
            alert.informativeText = "\(package.label) (\(package.eco)) \(package.reason)."
            if package.trustable { alert.addButton(withTitle: "Trust this version") }
        }
        NSApp.activate(ignoringOtherApps: true)
        return alert.runModal() == .alertSecondButtonReturn
    }
}

enum AdminAuthorization {
    /// The allowlist applies to every user of the Mac, so changing it takes an admin, as `sudo` would.
    static func confirm() -> Bool {
        var authorization: AuthorizationRef?
        guard AuthorizationCreate(nil, nil, [], &authorization) == errAuthorizationSuccess,
              let authorization else { return false }
        defer { AuthorizationFree(authorization, []) }
        return "system.preferences".withCString { name in
            var item = AuthorizationItem(name: name, valueLength: 0, value: nil, flags: 0)
            return withUnsafeMutablePointer(to: &item) { item in
                var rights = AuthorizationRights(count: 1, items: item)
                let flags: AuthorizationFlags = [.interactionAllowed, .extendRights]
                return AuthorizationCopyRights(authorization, &rights, nil, flags, nil) == errAuthorizationSuccess
            }
        }
    }
}
