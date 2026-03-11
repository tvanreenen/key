import AppKit
import Foundation
import KeyCore

final class SystemClipboardWriter: ClipboardWriting {
    func copy(_ text: String) throws {
        let pasteboard = NSPasteboard.general
        pasteboard.clearContents()
        guard pasteboard.setString(text, forType: .string) else {
            throw AppError.io("Failed to write to the pasteboard.")
        }
    }
}
