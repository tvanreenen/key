import Foundation

public enum Command: Equatable {
    case help
    case version(json: Bool)
    case unlock
    case lock
    case get(name: String)
    case copy(name: String)
    case add(name: String)
    case edit(name: String)
    case duplicate(source: String, destination: String, force: Bool)
    case rename(source: String, destination: String, force: Bool)
    case remove(name: String, force: Bool)
    case list
}
