import Foundation

public final class HelperLifecycleController: @unchecked Sendable {
    private let idleTimeout: TimeInterval
    private let queue = DispatchQueue(label: "work.tvr.key.helper-lifecycle")
    private let onIdle: () -> Void
    private var timer: DispatchSourceTimer?
    private var activeRequestCount = 0
    private var idleDeadline: DispatchTime?
    private var isShuttingDown = false

    public init(idleTimeout: TimeInterval, onIdle: @escaping () -> Void) {
        precondition(idleTimeout > 0, "The helper idle timeout must be positive.")
        self.idleTimeout = idleTimeout
        self.onIdle = onIdle
    }

    public func start() {
        queue.sync {
            precondition(idleDeadline == nil, "The helper lifecycle can only be started once.")
            idleDeadline = .now() + idleTimeout
            scheduleTimerIfIdle()
        }
    }

    public func beginRequest(extendsIdleDeadline: Bool) {
        queue.sync {
            precondition(!isShuttingDown, "Cannot begin a request while the helper is shutting down.")
            activeRequestCount += 1
            timer?.cancel()
            timer = nil
            if extendsIdleDeadline {
                idleDeadline = .now() + idleTimeout
            }
        }
    }

    public func endRequest(extendsIdleDeadline: Bool) {
        queue.sync {
            precondition(activeRequestCount > 0, "Unbalanced helper request lifecycle.")
            activeRequestCount -= 1
            if extendsIdleDeadline {
                idleDeadline = .now() + idleTimeout
            }
            scheduleTimerIfIdle()
        }
    }

    public func shutdown() {
        queue.async {
            guard !self.isShuttingDown else {
                return
            }
            self.isShuttingDown = true
            self.timer?.cancel()
            self.timer = nil
            self.onIdle()
        }
    }

    private func scheduleTimerIfIdle() {
        guard !isShuttingDown, activeRequestCount == 0, let idleDeadline else {
            return
        }

        timer?.cancel()

        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: idleDeadline)
        timer.setEventHandler { [weak self] in
            guard let self, !self.isShuttingDown, self.activeRequestCount == 0 else {
                return
            }
            self.isShuttingDown = true
            self.timer = nil
            self.onIdle()
        }
        timer.resume()
        self.timer = timer
    }
}
