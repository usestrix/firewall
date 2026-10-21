import CryptoKit
import Foundation
import Security

private enum TrustStoreError: Error, LocalizedError {
    case malformedPEM
    case malformedCertificate
    case security(String, OSStatus)

    var errorDescription: String? {
        switch self {
        case .malformedPEM:
            return "The extension did not return a PEM certificate"
        case .malformedCertificate:
            return "Certificate data was not valid DER"
        case let .security(call, status):
            let detail = SecCopyErrorMessageString(status, nil) as String? ?? "status \(status)"
            return "\(call) failed: \(detail)"
        }
    }
}

enum TrustStore {
    static func certificate(pem: String) throws -> SecCertificate {
        guard let begin = pem.range(of: "-----BEGIN CERTIFICATE-----"),
              let end = pem.range(of: "-----END CERTIFICATE-----", range: begin.upperBound ..< pem.endIndex),
              let der = Data(base64Encoded: String(pem[begin.upperBound ..< end.lowerBound]),
                             options: .ignoreUnknownCharacters)
        else { throw TrustStoreError.malformedPEM }

        guard let certificate = SecCertificateCreateWithData(nil, der as CFData) else {
            throw TrustStoreError.malformedCertificate
        }
        return certificate
    }

    /// The extension only uses a managed CA after checking that it chains to a root the MDM trusts.
    static func isTrusted(_ certificate: SecCertificate) -> Bool {
        var name: CFString?
        if SecCertificateCopyCommonName(certificate, &name) == errSecSuccess,
           name as String? == FirewallIDs.managedCaCommonName { return true }
        var settings: CFArray?
        return SecTrustSettingsCopyTrustSettings(certificate, .admin, &settings) == errSecSuccess
    }

    /// Scoped to SSL rather than "any usage", so a leaked key cannot sign code or email.
    static func trust(_ certificate: SecCertificate) throws {
        let settings: [[String: Any]] = [[
            kSecTrustSettingsPolicy as String: SecPolicyCreateSSL(true, nil),
            kSecTrustSettingsResult as String: SecTrustSettingsResult.trustRoot.rawValue,
        ]]
        let status = SecTrustSettingsSetTrustSettings(certificate, .admin, settings as CFArray)
        guard status == errSecSuccess else {
            throw TrustStoreError.security("SecTrustSettingsSetTrustSettings", status)
        }
    }

    static func untrust(_ certificate: SecCertificate) throws {
        let status = SecTrustSettingsRemoveTrustSettings(certificate, .admin)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw TrustStoreError.security("SecTrustSettingsRemoveTrustSettings", status)
        }
    }

    /// Matched by name because trust settings outlive the CA: a re-mint would otherwise leave the old root trusted.
    static func trustedAuthorities(commonName: String) -> [SecCertificate] {
        var copied: CFArray?
        guard SecTrustSettingsCopyCertificates(.admin, &copied) == errSecSuccess,
              let certificates = copied as? [SecCertificate]
        else { return [] }

        return certificates.filter { certificate in
            var name: CFString?
            guard SecCertificateCopyCommonName(certificate, &name) == errSecSuccess else { return false }
            return name as String? == commonName
        }
    }

    static func fingerprint(_ certificate: SecCertificate) -> String {
        let digest = SHA256.hash(data: SecCertificateCopyData(certificate) as Data)
        return digest.map { String(format: "%02X", $0) }.joined(separator: ":")
    }
}
