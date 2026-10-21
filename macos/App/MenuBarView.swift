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
    }
}
