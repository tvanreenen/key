import Foundation

public protocol ClipboardWriting {
    func copy(_ text: String) throws
}
