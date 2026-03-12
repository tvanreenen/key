import Foundation

public enum Command: Equatable {
    case show(name: String, copy: Bool)
    case put(name: String, mode: PutMode, force: Bool)
    case list
}
