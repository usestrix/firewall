import SwiftUI

struct MenuBarView: View {
    @ObservedObject var model: InstallerModel
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        Text(model.screening ? "Screening downloads" : "Not running")

        Divider()

        Button("Installer") {
            SetupWindow.open(openWindow)
        }

        Button("Restart") {
            Task { await model.restart() }
        }
        .disabled(model.busy)

        Button("Uninstall") {
            Task { await model.uninstall() }
        }
        .disabled(model.busy)

        Divider()

        Button("Quit Firewall") {
            NSApplication.shared.terminate(nil)
        }
        .keyboardShortcut("q")
    }
}
