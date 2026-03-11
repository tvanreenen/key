import Foundation

public enum Command: Equatable {
    case get(name: String, copy: Bool)
    case put(name: String, mode: PutMode, force: Bool)
    case list
}
