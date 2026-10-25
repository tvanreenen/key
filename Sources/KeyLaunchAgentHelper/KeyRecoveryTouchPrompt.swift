import AppKit
import KeyCore

/// One request's presentation, never an approval source. Native authentication
/// remains in KeyCore; this window has no PIN field or Continue/OK button.
final class KeyRecoveryTouchPrompt: @unchecked Sendable {
    private let lock = NSLock()
    private var closed = false
    private let cancelRequest: @Sendable () -> Void
    @MainActor private var window: TouchWindow?

    init(cancelRequest: @escaping @Sendable () -> Void) { self.cancelRequest = cancelRequest }

    func receive(_ stage: KeyRecoveryStage) {
        switch stage {
        case .authenticating, .touchRequired:
            // The worker holds no state/native lock here. Show before admitting
            // the exchange so an unavailable UI can cancel without a new call.
            DispatchQueue.main.sync {
                guard lock.withLock({ !closed }) else { return }
                guard NSApplication.shared.activationPolicy() != .prohibited else {
                    cancel()
                    return
                }
                if stage == .touchRequired {
                    let view = TouchWindow { [weak self] in self?.cancel() }
                    window = view
                    view.show()
                }
            }
        case .hardwareCompleted:
            finish()
        }
    }

    func finish() {
        lock.withLock { closed = true }
        DispatchQueue.main.async { [self] in
            window?.dismiss()
            window = nil
        }
    }

    private func cancel() {
        finish()
        cancelRequest()
    }

    @MainActor private final class TouchWindow: NSObject, NSWindowDelegate {
        private let alert = NSAlert()
        private let cancelRequest: () -> Void

        init(cancelRequest: @escaping () -> Void) {
            self.cancelRequest = cancelRequest
            super.init()
            alert.messageText = "Touch your YubiKey"
            alert.informativeText = "Touch its flashing metal contact to continue. This window closes when the key operation finishes."
            alert.alertStyle = .informational
            let button = alert.addButton(withTitle: "Cancel")
            button.target = self
            button.action = #selector(cancel)
            button.keyEquivalent = "\u{1b}"
            let indicator = NSProgressIndicator(frame: NSRect(x: 0, y: 0, width: 24, height: 24))
            indicator.style = .spinning
            indicator.startAnimation(nil)
            alert.accessoryView = indicator
            // Complete lazy layout before presenting the window directly.
            alert.layout()
            alert.window.delegate = self
            alert.window.title = "Key Recovery"
        }

        func show() {
            alert.window.center()
            alert.window.makeKeyAndOrderFront(nil)
            NSApplication.shared.activate()
        }
        func dismiss() { alert.window.orderOut(nil) }
        @objc private func cancel() { cancelRequest() }
        func windowShouldClose(_ sender: NSWindow) -> Bool {
            cancelRequest()
            return false
        }
    }
}
