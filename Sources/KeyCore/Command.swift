import Foundation

public enum Command: Equatable {
    case show(name: String, copy: Bool)
    case add(name: String, mode: PutMode)
    case list
}
