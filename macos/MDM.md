# Deploying with MDM

On a managed Mac the firewall can use a CA your MDM enrolls instead of minting its own, so users
need no admin rights and see no trust prompt. Each Mac still has its own key in its Secure Enclave;
your PKI signs its certificate.

Push one device-channel profile with:

1. **Certificate** (`com.apple.security.root`): your root CA.
2. **ACME Certificate** (`com.apple.security.acme`), macOS 14 or later:
   - `KeyType` `ECSECPrimeRandom`, `KeySize` `256`, `HardwareBound` `true`, `Attest` `true`
   - `Subject` `[[["CN", "Strix Firewall Managed"]]]`; the extension finds the identity by this name
   - `AllowAllAppsAccess` `true`, so the extension can sign with the key
3. **System Extensions**: allow `com.usestrix.firewall.extension` for the Strix team ID.

Your ACME server must issue the enrolled certificate as a CA, not a leaf:

- basic constraints `CA:TRUE, pathlen:0` and key usage `keyCertSign`
- critical name constraints permitting only the screened hosts: `registry.npmjs.org`, `pypi.org`,
  `files.pythonhosted.org`, `index.crates.io`, `static.crates.io`, `crates.io`,
  `proxy.golang.org`, `rubygems.org`

The extension checks the certificate chains to a trusted root before using it. Install the profile
before the firewall: without a managed CA the extension mints its own, which needs an admin to trust.
