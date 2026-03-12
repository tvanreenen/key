import Foundation

public enum Command: Equatable {
    case show(name: String, copy: Bool)
    case add(name: String)
    case edit(name: String)
    case copy(source: String, destination: String, force: Bool)
    case move(source: String, destination: String, force: Bool)
    case remove(name: String, force: Bool)
    case list
}
