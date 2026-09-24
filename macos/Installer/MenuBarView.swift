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

        Button(model.screening ? "Pause" : "Resume") {
            Task { await model.setEnabled(!model.screening) }
        }
        .disabled(model.busy || !model.configured)

        Button("Restart") {
            Task { await model.restart() }
        }
        .disabled(model.busy)
    }
}
