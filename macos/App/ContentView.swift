import SwiftUI

struct ContentView: View {
    @ObservedObject var model: FirewallModel
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
            Divider()
            steps
            Divider()
            transcript
            Divider()
            footer
        }
        .frame(width: 540, height: 560)
        .task { await model.refresh() }
        .onAppear(perform: recenterIfOffscreen)
        .onChange(of: model.completed) { done in
            guard done else { return }
            Task {
                // Let the success show before the window closes; the app stays in the menu bar.
                try? await Task.sleep(nanoseconds: 800_000_000)
                dismiss()
            }
        }
    }

    /// A frame saved on a display that is no longer attached leaves the window unreachable.
    private func recenterIfOffscreen() {
        DispatchQueue.main.async {
            for window in NSApplication.shared.windows where window.title == SetupWindow.title && window.screen == nil {
                window.center()
            }
        }
    }

    private var header: some View {
        HStack(spacing: 14) {
            Image(nsImage: NSImage(named: "logo-transparent")!)
                .renderingMode(.template)
                .resizable()
                .scaledToFit()
                .frame(height: 40)
            VStack(alignment: .leading, spacing: 3) {
                Text("Firewall").font(.title2.weight(.semibold))
                Text("Screens package downloads before they reach your machine.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
            Spacer()
        }
        .padding(20)
    }

    private var steps: some View {
        VStack(spacing: 18) {
            StepRow(index: 1,
                    title: "Install the system extension",
                    note: "macOS will ask you to approve it in System Settings.",
                    status: model.extensionStep)
            StepRow(index: 2,
                    title: "Turn on screening",
                    note: "macOS will ask you to allow a network configuration.",
                    status: model.screeningStep)
            StepRow(index: 3,
                    title: "Trust the local certificate authority",
                    note: "Minted on this Mac by the extension. The private key never leaves the Secure Enclave.",
                    status: model.trustStep)
        }
        .padding(20)
    }

    private var transcript: some View {
        ScrollViewReader { proxy in
            ScrollView {
                VStack(alignment: .leading, spacing: 2) {
                    ForEach(model.transcript.indices, id: \.self) { line in
                        Text(model.transcript[line])
                            .font(.system(.caption, design: .monospaced))
                            .foregroundStyle(.secondary)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .id(line)
                    }
                }
                .padding(12)
            }
            .onChange(of: model.transcript.count) { count in
                proxy.scrollTo(count - 1)
            }
        }
        .frame(maxHeight: .infinity)
    }

    private var footer: some View {
        HStack {
            if model.busy { ProgressView().controlSize(.small) }
            if model.completed {
                Label("Firewall is set up. It lives in the menu bar now.", systemImage: "checkmark.circle.fill")
                    .foregroundStyle(.green)
                    .font(.callout)
            } else if model.removed {
                Label("Firewall is uninstalled. Reboot to finish removing the extension.",
                      systemImage: "trash.circle.fill")
                    .foregroundStyle(.secondary)
                    .font(.callout)
            }
            Spacer()
            Button("Uninstall") { Task { await model.uninstall() } }
                .disabled(model.busy && !model.awaitingApproval)
            Button("Install") { Task { await model.install() } }
                .keyboardShortcut(.defaultAction)
                .disabled(model.busy || model.completed)
        }
        .padding(16)
    }
}

private struct StepRow: View {
    let index: Int
    let title: String
    let note: String
    let status: StepStatus

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            indicator
                .frame(width: 22, height: 22)
            VStack(alignment: .leading, spacing: 3) {
                Text(title).font(.body.weight(.medium))
                Text(note).font(.caption).foregroundStyle(.secondary)
                Text(status.detail)
                    .font(font)
                    .foregroundStyle(tint)
                    .textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer()
        }
    }

    @ViewBuilder
    private var indicator: some View {
        switch status {
        case .pending:
            Text("\(index)")
                .font(.caption.weight(.semibold))
                .foregroundStyle(.secondary)
                .frame(width: 20, height: 20)
                .overlay(Circle().strokeBorder(.secondary.opacity(0.4)))
        case .running, .needsAction:
            ProgressView().controlSize(.small)
        case .done:
            Image(systemName: "checkmark.circle.fill").foregroundStyle(.green)
        case .failed:
            Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.orange)
        }
    }

    private var font: Font {
        if case .needsAction = status { return .title3 }
        return .caption
    }

    private var tint: Color {
        switch status {
        case .pending, .running: return .secondary
        case .needsAction: return .orange
        case .done: return .green
        case .failed: return .orange
        }
    }
}
