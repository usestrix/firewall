import SwiftUI

@main
struct FirewallApp: App {
    @StateObject private var model = FirewallModel()

    var body: some Scene {
        MenuBarExtra {
            MenuBarView(model: model)
        } label: {
            MenuBarLabel(model: model)
        }

        Window(SetupWindow.title, id: SetupWindow.id) {
            ContentView(model: model)
        }
        .windowResizability(.contentSize)
    }
}

enum SetupWindow {
    static let id = "setup"
    static let title = "Firewall Setup"

    /// An accessory app has no Dock icon to click, so the window has to raise itself.
    @MainActor static func open(_ openWindow: OpenWindowAction) {
        NSApplication.shared.activate(ignoringOtherApps: true)
        openWindow(id: id)
    }
}

/// An accessory app restores no windows, so setup is raised from the label, the one view built at launch.
private struct MenuBarLabel: View {
    @ObservedObject var model: FirewallModel
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        Image(nsImage: Self.icon).task {
            await model.refresh()
            guard !model.configured else { return }
            SetupWindow.open(openWindow)
        }
    }

    /// Drawn from the alpha channel so it follows the theme, at the 15pt SF Symbols use in the 22pt menu bar.
    private static let icon: NSImage = {
        let image = NSImage(named: "logo-transparent")
            ?? NSImage(systemSymbolName: "shield.lefthalf.filled", accessibilityDescription: "Firewall")!
        let height: CGFloat = 15
        image.size = NSSize(width: height * image.size.width / image.size.height, height: height)
        image.isTemplate = true
        return image
    }()
}
