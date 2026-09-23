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

enum InstallerError: Error, LocalizedError {
    case extensionUnavailable
    case extensionRefused(String)
    case screeningDidNotStart(NEVPNStatus)

    var errorDescription: String? {
        switch self {
        case .extensionUnavailable: return "The extension is not running"
        case let .extensionRefused(reply): return "The extension replied \(reply)"
        case let .screeningDidNotStart(status): return "Screening did not start, state \(status.rawValue)"
        }
    }
}

@MainActor
final class InstallerModel: NSObject, ObservableObject {
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
    private var watched: NETransparentProxyManager?

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
                screeningStep = .done("Enabled, state \(manager.connection.status.rawValue)")
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

    /// Every stage runs even if an earlier one fails, so a partial uninstall never strands the rest.
    func uninstall() async {
        busy = true
        defer { busy = false }
        completed = false
        removed = false

        // The extension owns the private key, so ask it before tearing down the session that carries the request.
        let strandedKey = await removeStoredCA()
        await removeConfiguration()
        await deactivate()
        untrustAuthorities()
        if let strandedKey { trustStep = .failed(strandedKey) }

        let failed = [extensionStep, screeningStep, trustStep].contains(where: \.isFailed)
        removed = !failed
        log(failed ? "Uninstall finished with errors" : "Uninstall complete")
    }

    /// Restarting the tunnel rebuilds the provider, which is what makes it re-read the config.
    func restart() async {
        busy = true
        defer { busy = false }
        _ = await stage(\.screeningStep, running: "Restarting screening", work: restartScreening)
    }

    private func stage(_ step: ReferenceWritableKeyPath<InstallerModel, StepStatus>,
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
        } catch {
            extensionStep = .failed(error.localizedDescription)
            log("Deactivation failed: \(error.localizedDescription)")
        }
    }

    private func untrustAuthorities() {
        trustStep = .running("Removing certificate trust")
        let authorities = TrustStore.trustedAuthorities(commonName: FirewallIDs.caCommonName)
        guard !authorities.isEmpty else {
            log("No trusted Firewall certificate authorities found")
            trustStep = .pending
            return
        }

        var failure: String?
        for authority in authorities {
            do {
                try TrustStore.untrust(authority)
                log("Trust removed for \(TrustStore.fingerprint(authority))")
            } catch {
                failure = error.localizedDescription
                log("Untrust failed: \(error.localizedDescription)")
            }
        }
        trustStep = failure.map(StepStatus.failed) ?? .pending
    }

    /// Only root can delete the key, so the extension does it; returns what to report if it survived.
    private func removeStoredCA() async -> String? {
        do {
            let reply = try await providerMessage("uninstall")
            guard reply == "ok" else { throw InstallerError.extensionRefused(reply) }
            log("Removed the CA, its exported copy and the env agent")
            return nil
        } catch {
            log("Could not remove the CA: \(error.localizedDescription)")
            return "The CA private key is still in the System keychain"
        }
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

        try manager.connection.startVPNTunnel()
        guard try await wait(for: .connected, on: manager.connection) else {
            throw InstallerError.screeningDidNotStart(manager.connection.status)
        }
        return "Screening package downloads"
    }

    private func restartScreening() async throws -> String {
        guard let manager = try await loadManager() else {
            throw InstallerError.extensionUnavailable
        }
        manager.connection.stopVPNTunnel()
        _ = try await wait(for: .disconnected, on: manager.connection)
        return try await startScreening()
    }

    private func wait(for status: NEVPNStatus, on connection: NEVPNConnection) async throws -> Bool {
        for _ in 0 ..< 60 {
            if connection.status == status { return true }
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
        return TrustStore.fingerprint(certificate)
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
            throw InstallerError.extensionUnavailable
        }
        return try await withCheckedThrowingContinuation { continuation in
            do {
                try session.sendProviderMessage(Data(message.utf8)) { response in
                    guard let response, let reply = String(data: response, encoding: .utf8) else {
                        continuation.resume(throwing: InstallerError.extensionUnavailable)
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

extension InstallerModel: OSSystemExtensionRequestDelegate {
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
