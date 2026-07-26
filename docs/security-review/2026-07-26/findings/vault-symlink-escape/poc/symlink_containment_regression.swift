import Foundation

enum ProbeError: Error {
    case invalidName
    case unexpectedContainment
    case markerMissing
}

// Mirrors the relevant lexical checks and URL construction in EntryStore.
func currentURL(root: URL, name: String) throws -> URL {
    let normalized = name.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !normalized.isEmpty, !normalized.hasPrefix("/") else {
        throw ProbeError.invalidName
    }
    let components = normalized.split(
        separator: "/",
        omittingEmptySubsequences: false
    )
    guard components.allSatisfy({
        !$0.isEmpty && $0 != "." && $0 != ".."
    }) else {
        throw ProbeError.invalidName
    }
    let parent = components.dropLast().reduce(root) { partial, component in
        partial.appendingPathComponent(String(component), isDirectory: true)
    }
    return parent
        .appendingPathComponent(String(components.last!), isDirectory: false)
        .appendingPathExtension("secret")
}

func resolvedParentIsContained(destination: URL, root: URL) -> Bool {
    let resolvedRoot = root.resolvingSymlinksInPath().standardizedFileURL
    let resolvedParent = destination
        .deletingLastPathComponent()
        .resolvingSymlinksInPath()
        .standardizedFileURL
    let rootComponents = resolvedRoot.pathComponents
    let parentComponents = resolvedParent.pathComponents
    return parentComponents.count >= rootComponents.count
        && Array(parentComponents.prefix(rootComponents.count)) == rootComponents
}

let fileManager = FileManager.default
let sandbox = fileManager.temporaryDirectory
    .appendingPathComponent(
        "key-symlink-regression-\(UUID().uuidString)",
        isDirectory: true
    )
let vault = sandbox.appendingPathComponent("vault", isDirectory: true)
let outside = sandbox.appendingPathComponent("outside", isDirectory: true)
let link = vault.appendingPathComponent("team", isDirectory: true)

try fileManager.createDirectory(at: vault, withIntermediateDirectories: true)
try fileManager.createDirectory(at: outside, withIntermediateDirectories: true)
defer {
    try? fileManager.removeItem(at: sandbox)
}

try fileManager.createSymbolicLink(at: link, withDestinationURL: outside)

let destination = try currentURL(root: vault, name: "team/probe")
let contained = resolvedParentIsContained(destination: destination, root: vault)
print("[+] lexical validation accepted team/probe")
print("[+] resolved parent is contained: \(contained)")

guard !contained else {
    throw ProbeError.unexpectedContainment
}

// The marker is intentionally harmless and both directories are disposable.
try Data("containment-regression".utf8).write(to: destination, options: .atomic)
let outsideMarker = outside.appendingPathComponent(
    "probe.secret",
    isDirectory: false
)
guard fileManager.fileExists(atPath: outsideMarker.path) else {
    throw ProbeError.markerMissing
}

print("[!] Foundation write landed outside lexical vault root: true")
print("[+] defensive resolved-parent check would reject destination")
print("[+] disposable sandbox cleanup scheduled")
