import SwiftUI

struct MenuBarView: View {
    @ObservedObject var model: FirewallModel
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        Text(model.screening ? "Screening downloads" : "Not running")

        Divider()

        Button("Setup") {
            SetupWindow.open(openWindow)
        }

        Button(model.screening ? "Pause" : "Resume") {
            Task { await model.setEnabled(!model.screening) }
        }
        .disabled(model.busy || !model.configured)

        Button("Restart") {
            Task { await model.restart() }
        }
        .disabled(model.busy)

        if !model.blocked.isEmpty {
            Divider()
            ForEach(model.blocked) { package in
                if !package.malicious {
                    Menu("Held back \(package.label) (\(package.eco))") {
                        Text(package.reason)
                        Button("Allow Once") {
                            Task { await model.allow(package, .once) }
                        }
                        .disabled(model.busy || !package.trustable)
                        Button("Trust this version") {
                            Task { await model.allow(package, .always) }
                        }
                        .disabled(model.busy || !package.trustable)
                    }
                } else {
                    Menu("Blocked \(package.label) (\(package.eco))") {
                        Text("Malicious: \(package.reason)")
                    }
                }
            }
        }
    }
}
