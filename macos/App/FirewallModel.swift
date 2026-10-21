import AppKit
import NetworkExtension
import OSLog
import Security
import SystemExtensions

enum StepStatus: Equatable {
    case pending
    case running(String)
    case done(String)
    case failed(String)

    var detail: String {
        switch self {
        case .pending: return "Not started"
        case let .running(text), let .done(text), let .failed(text): return text
        }
    }

    var isFailed: Bool {
        if case .failed = self { return true }
        return false
    }
}

enum FirewallError: Error, LocalizedError {
    case extensionUnavailable
    case screeningDidNotStart(NEVPNStatus)
    case extensionStopped(String)

    var errorDescription: String? {
        switch self {
        case .extensionUnavailable: return "The extension is not running"
        case let .screeningDidNotStart(status): return "Screening did not start (\(status.label))"
        case let .extensionStopped(reason):
            return "The extension stopped: \(reason). Its log: log show --last 5m --predicate 'subsystem BEGINSWITH \"\(FirewallIDs.appBundleID)\"'"
        }
    }
}

@MainActor
final class FirewallModel: NSObject, ObservableObject {
    @Published private(set) var extensionStep = StepStatus.pending
    @Published private(set) var screeningStep = StepStatus.pending
    @Published private(set) var trustStep = StepStatus.pending
    @Published private(set) var busy = false
    @Published private(set) var completed = false
    @Published private(set) var removed = false
    @Published private(set) var transcript: [String] = []
    @Published private(set) var screening = false

    private let logger = Logger(subsystem: FirewallIDs.appBundleID, category: "installer")
    private var pendingRequest: CheckedContinuation<Void, Error>?
    private var statusObserver: NSObjectProtocol?
    // NE only posts status notifications for connections that are still referenced.
    @Published private var watched: NETransparentProxyManager?
    var configured: Bool { watched != nil }

    override init() {
        super.init()
        statusObserver = NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange, object: nil, queue: .main
        ) { [weak self] note in
            guard let connection = note.object as? NEVPNConnection else { return }
            let running = connection.status == .connected
            Task { @MainActor in self?.screening = running }
        }
        Task {
            await refresh()
            if CommandLine.arguments.contains("--install") { await install() }
        }
    }

    // MARK: - Flows

    func refresh() async {
        if let manager = try? await loadManager() {
            watched = manager
            if manager.isEnabled {
                screeningStep = .done("Enabled (\(manager.connection.status.label))")
            }
            screening = manager.connection.status == .connected
        }
        if let pem = try? await providerMessage("ca"), let certificate = try? TrustStore.certificate(pem: pem),
           TrustStore.isTrusted(certificate) {
            trustStep = .done(TrustStore.fingerprint(certificate))
        }
    }

    func install() async {
        busy = true
        defer { busy = false }
        removed = false

        guard CompetingExtensions.confirmInstall() else {
            log("Install cancelled: other network extensions are active")
            return
        }

        guard await stage(\.extensionStep, running: "Submitting activation request",
                          work: {
                              try await self.submit(.activationRequest(
                                  forExtensionWithIdentifier: FirewallIDs.extensionBundleID, queue: .main))
                              return "Activated"
                          }),
              await stage(\.screeningStep, running: "Saving the network configuration",
                          work: startScreening),
              await stage(\.trustStep, running: "Waiting for the extension's CA",
                          work: trustCertificateAuthority)
        else { return }

        completed = true
        log("Setup complete")
    }

    /// After the admin gate, every stage runs even if an earlier one fails, so a partial uninstall never strands the rest.
    func uninstall() async {
        busy = true
        defer { busy = false }
        completed = false
        removed = false

        // Install needs admin, so uninstall does too: untrusting the CA prompts for it, and a cancel stops here.
        guard await untrustAuthorities() else {
            log("Uninstall cancelled")
            return
        }
        // Stop screening first so the extension cannot mint a fresh CA after it is removed.
        await removeConfiguration()
        let strandedKey = removeStoredCA()
        await deactivate()
        if let strandedKey { trustStep = .failed(strandedKey) }

        let failed = [extensionStep, screeningStep, trustStep].contains(where: \.isFailed)
        removed = !failed
        log(failed ? "Uninstall finished with errors" : "Uninstall complete")
        guard removed else { return }

        do {
            try FileManager.default.trashItem(at: Bundle.main.bundleURL, resultingItemURL: nil)
        } catch {
            log("Could not move the app to the Trash: \(error.localizedDescription)")
        }
        let alert = NSAlert()
        alert.messageText = "Firewall is uninstalled"
        alert.informativeText = "Reboot to finish removing the extension."
        NSApp.activate(ignoringOtherApps: true)
        alert.runModal()
        NSApp.terminate(nil)
    }

    /// Restarting the tunnel rebuilds the provider, which is what makes it re-read the config.
    func restart() async {
        busy = true
        defer { busy = false }
        guard await stage(\.screeningStep, running: "Restarting screening", work: restartScreening) else { return }
        // A restart can mint a new CA when the screened hosts change.
        _ = await stage(\.trustStep, running: "Waiting for the extension's CA", work: trustCertificateAuthority)
    }

    func setEnabled(_ enabled: Bool) async {
        busy = true
        defer { busy = false }
        if enabled {
            _ = await stage(\.screeningStep, running: "Starting screening", work: startScreening)
        } else {
            _ = await stage(\.screeningStep, running: "Stopping screening", work: stopScreening)
        }
    }

    private func stage(_ step: ReferenceWritableKeyPath<FirewallModel, StepStatus>,
                       running: String,
                       work: @MainActor () async throws -> String) async -> Bool {
        self[keyPath: step] = .running(running)
        do {
            let done = try await work()
            self[keyPath: step] = .done(done)
            log(done)
            return true
        } catch {
            self[keyPath: step] = .failed(error.localizedDescription)
            log(error.localizedDescription)
            return false
        }
    }

    private func removeConfiguration() async {
        screeningStep = .running("Stopping screening")
        do {
            guard let manager = try await loadManager() else {
                log("No network configuration to remove")
                screeningStep = .pending
                return
            }
            manager.connection.stopVPNTunnel()
            manager.isEnabled = false
            try await manager.removeFromPreferences()
            log("Network configuration removed")
            screeningStep = .pending
        } catch {
            screeningStep = .failed(error.localizedDescription)
            log("Config removal failed: \(error.localizedDescription)")
        }
        watched = nil
        screening = false
    }

    private func deactivate() async {
        extensionStep = .running("Deactivating the system extension")
        do {
            try await submit(.deactivationRequest(
                forExtensionWithIdentifier: FirewallIDs.extensionBundleID, queue: .main))
            extensionStep = .pending
            log("System extension deactivated, macOS finishes removing it on the next reboot")
        } catch OSSystemExtensionError.extensionNotFound {
            extensionStep = .pending
            log("No system extension to deactivate")
        } catch {
            extensionStep = .failed(error.localizedDescription)
            log("Deactivation failed: \(error.localizedDescription)")
        }
    }

    private func untrustAuthorities() async -> Bool {
        trustStep = .running("Removing certificate trust")
        let authorities = TrustStore.trustedAuthorities(commonName: FirewallIDs.caCommonName)
        guard !authorities.isEmpty else {
            log("No trusted Firewall certificate authorities found")
            trustStep = .pending
            return true
        }

        // Live CA last, so a cancelled prompt leaves screening working.
        let pem = try? await providerMessage("ca")
        let live = pem.flatMap { try? TrustStore.certificate(pem: $0) }.map(TrustStore.fingerprint)
        let stale = authorities.filter { TrustStore.fingerprint($0) != live }
        let current = authorities.filter { TrustStore.fingerprint($0) == live }
        for authority in stale + current {
            do {
                try TrustStore.untrust(authority)
                log("Trust removed for \(TrustStore.fingerprint(authority))")
            } catch {
                trustStep = .failed(error.localizedDescription)
                log("Untrust failed: \(error.localizedDescription)")
                return false
            }
        }
        trustStep = .pending
        return true
    }

    /// The extension wrote these as root, so the bundled CLI removes them behind an admin prompt; returns what to report if it failed.
    private func removeStoredCA() -> String? {
        let cli = Bundle.main.path(forAuxiliaryExecutable: "firewall") ?? ""
        let script = "do shell script quoted form of \"\(cli)\" & \" uninstall\" with administrator privileges"
        var error: NSDictionary?
        NSAppleScript(source: script)?.executeAndReturnError(&error)
        if let error {
            log("Could not remove the CA: \(error[NSAppleScript.errorMessage] ?? error)")
            return "The CA private key is still in the System keychain"
        }
        log("Removed the CA, its exported copy and the env agent")
        return nil
    }

    // MARK: - System extension

    private func submit(_ request: OSSystemExtensionRequest) async throws {
        request.delegate = self
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            pendingRequest = continuation
            OSSystemExtensionManager.shared.submitRequest(request)
        }
    }

    private func finishRequest(_ result: Result<Void, Error>) {
        pendingRequest?.resume(with: result)
        pendingRequest = nil
    }

    // MARK: - Network extension

    private func loadManager() async throws -> NETransparentProxyManager? {
        try await NETransparentProxyManager.loadAllFromPreferences().first
    }

    private func startScreening() async throws -> String {
        let manager = try await loadManager() ?? NETransparentProxyManager()

        let configuration = NETunnelProviderProtocol()
        configuration.providerBundleIdentifier = FirewallIDs.extensionBundleID
        configuration.serverAddress = "127.0.0.1"

        manager.protocolConfiguration = configuration
        manager.localizedDescription = "Firewall"
        manager.isEnabled = true

        try await manager.saveToPreferences()
        // NE hands back a stale object after a save; reloading is required before start.
        try await manager.loadFromPreferences()
        watched = manager

        screeningStep = .running("Starting the extension")
        try manager.connection.startVPNTunnel()
        guard try await wait(for: .connected, on: manager.connection) else {
            do {
                try await manager.connection.fetchLastDisconnectError()
            } catch {
                throw FirewallError.extensionStopped(error.localizedDescription)
            }
            throw FirewallError.screeningDidNotStart(manager.connection.status)
        }
        return "Screening package downloads"
    }

    private func restartScreening() async throws -> String {
        guard let manager = try await loadManager() else {
            throw FirewallError.extensionUnavailable
        }
        manager.connection.stopVPNTunnel()
        _ = try await wait(for: .disconnected, on: manager.connection)
        return try await startScreening()
    }

    private func stopScreening() async throws -> String {
        guard let manager = try await loadManager() else { throw FirewallError.extensionUnavailable }
        manager.isEnabled = false
        try await manager.saveToPreferences()
        manager.connection.stopVPNTunnel()
        _ = try await wait(for: .disconnected, on: manager.connection)
        return "Screening disabled"
    }

    /// Gives up early once a start has failed, which shows as connecting then disconnected.
    private func wait(for status: NEVPNStatus, on connection: NEVPNConnection) async throws -> Bool {
        var connecting = false
        for _ in 0 ..< 60 {
            if connection.status == status { return true }
            if connection.status == .connecting { connecting = true }
            if connecting && connection.status == .disconnected { return false }
            try await Task.sleep(nanoseconds: 250_000_000)
        }
        return false
    }

    // MARK: - Certificate

    private func trustCertificateAuthority() async throws -> String {
        let pem = try await awaitCertificate()
        let certificate = try TrustStore.certificate(pem: pem)
        if !TrustStore.isTrusted(certificate) {
            trustStep = .running("Requesting authorization")
            try TrustStore.trust(certificate)
        }
        let fingerprint = TrustStore.fingerprint(certificate)
        // A stale root of the same name makes TLS clients that pick an issuer by name fail intermittently.
        for authority in TrustStore.trustedAuthorities(commonName: FirewallIDs.caCommonName)
        where TrustStore.fingerprint(authority) != fingerprint {
            try TrustStore.untrust(authority)
            log("Trust removed for stale \(TrustStore.fingerprint(authority))")
        }
        return fingerprint
    }

    /// NE can report the connection up a moment before the provider answers messages.
    private func awaitCertificate() async throws -> String {
        for _ in 0 ..< 59 {
            if let pem = try? await providerMessage("ca") { return pem }
            try await Task.sleep(nanoseconds: 250_000_000)
        }
        return try await providerMessage("ca")
    }

    private func providerMessage(_ message: String) async throws -> String {
        guard let session = watched?.connection as? NETunnelProviderSession else {
            throw FirewallError.extensionUnavailable
        }
        return try await withCheckedThrowingContinuation { continuation in
            do {
                try session.sendProviderMessage(Data(message.utf8)) { response in
                    guard let response, let reply = String(data: response, encoding: .utf8) else {
                        continuation.resume(throwing: FirewallError.extensionUnavailable)
                        return
                    }
                    continuation.resume(returning: reply)
                }
            } catch {
                continuation.resume(throwing: error)
            }
        }
    }

    private func log(_ line: String) {
        transcript.append("\(Date().formatted(date: .omitted, time: .standard))  \(line)")
        logger.info("\(line, privacy: .public)")
    }
}

extension FirewallModel: OSSystemExtensionRequestDelegate {
    nonisolated func request(_ request: OSSystemExtensionRequest,
                             actionForReplacingExtension existing: OSSystemExtensionProperties,
                             withExtension replacement: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction {
        .replace
    }

    nonisolated func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        Task { @MainActor in
            extensionStep = .running("Approve Firewall in System Settings › General › Login Items & Extensions")
            log("Waiting for user approval")
            // Only MDM can pre-approve a system extension, so take them to the switch.
            if let pane = URL(string: "x-apple.systempreferences:com.apple.ExtensionsPreferences?extensionPointIdentifier=com.apple.system_extension.network_extension") {
                NSWorkspace.shared.open(pane)
            }
        }
    }

    nonisolated func request(_ request: OSSystemExtensionRequest,
                             didFinishWithResult result: OSSystemExtensionRequest.Result) {
        Task { @MainActor in
            if result == .willCompleteAfterReboot {
                log("Extension will finish installing after a reboot")
            }
            finishRequest(.success(()))
        }
    }

    nonisolated func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        Task { @MainActor in finishRequest(.failure(error)) }
    }
}

private extension NEVPNStatus {
    var label: String {
        switch self {
        case .invalid: return "not configured"
        case .disconnected: return "disconnected"
        case .connecting: return "connecting"
        case .connected: return "connected"
        case .reasserting: return "reconnecting"
        case .disconnecting: return "disconnecting"
        @unknown default: return "unknown"
        }
    }
}
