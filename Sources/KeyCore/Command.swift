import Foundation

public enum Command: Equatable {
    case show(name: String, copy: Bool)
    case add(name: String, mode: PutMode)
    case edit(name: String, mode: PutMode)
    case copy(source: String, destination: String, force: Bool)
    case list
}
