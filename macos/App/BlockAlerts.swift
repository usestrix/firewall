import AppKit
import Security

struct BlockedPackage: Codable, Hashable, Identifiable {
    let id: UInt64
    let eco: String
    let name: String
    let version: String?
    let filter: String
    let reason: String

    var label: String { version.map { "\(name) \($0)" } ?? name }
    /// The denylist and OSV only flag packages known to be malicious; the age check only holds back new ones.
    var malicious: Bool { filter != "age" }
    /// Malware is never allowed, and a new package only by version.
    var trustable: Bool { !malicious && version != nil }
}

enum Allowance {
    /// For a minute, so the rest of that install can fetch it too.
    case once
    case always
}

@MainActor
enum BlockAlert {
    static func show(_ package: BlockedPackage) -> Allowance? {
        let alert = NSAlert()
        alert.addButton(withTitle: "OK")
        if package.malicious {
            alert.alertStyle = .critical
            alert.messageText = "Blocked malware: \(package.label) (\(package.eco))"
            setText(alert, "\(package.label) \(package.reason).\n\n"
                + "It was not installed. Don't install it from another source. "
                + "If you didn't expect this package, a dependency may be compromised; tell your security team.")
        } else {
            alert.messageText = "Held back a new package"
            setText(alert, "\(package.label) (\(package.eco)) \(package.reason).")
            if package.trustable {
                alert.addButton(withTitle: "Allow Once")
                alert.addButton(withTitle: "Trust this version")
            }
        }
        NSApp.activate(ignoringOtherApps: true)
        switch alert.runModal() {
        case .alertSecondButtonReturn: return .once
        case .alertThirdButtonReturn: return .always
        default: return nil
        }
    }

    static func late(_ package: BlockedPackage, _ allowance: Allowance) {
        let alert = NSAlert()
        alert.messageText = allowance == .once ? "Allowed \(package.label) for the next minute" : "Trusted \(package.label)"
        alert.informativeText = "The install had already stopped waiting for it. Run it again to finish."
        NSApp.activate(ignoringOtherApps: true)
        alert.runModal()
    }

    /// An alert's own text is plain, so this text goes in a selectable field, where its links open on click.
    private static func setText(_ alert: NSAlert, _ text: String) {
        let linked = NSMutableAttributedString(string: text, attributes: [.font: NSFont.systemFont(ofSize: NSFont.smallSystemFontSize)])
        let detector = try! NSDataDetector(types: NSTextCheckingResult.CheckingType.link.rawValue)
        for match in detector.matches(in: text, range: NSRange(text.startIndex..., in: text)) {
            if let url = match.url { linked.addAttribute(.link, value: url, range: match.range) }
        }
        let field = NSTextField(wrappingLabelWithString: "")
        field.allowsEditingTextAttributes = true
        field.isSelectable = true
        field.attributedStringValue = linked
        field.preferredMaxLayoutWidth = 300
        field.frame.size = field.fittingSize
        alert.accessoryView = field
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
