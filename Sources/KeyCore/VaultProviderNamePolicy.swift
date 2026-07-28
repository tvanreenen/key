import Foundation

enum VaultProviderCaseSensitivity: Equatable, Sendable {
    case sensitive
    case insensitive
}

enum VaultProviderNamePolicyError: Error, Equatable, LocalizedError {
    case collision(first: String, second: String)

    var errorDescription: String? {
        switch self {
        case let .collision(first, second):
            return "Vault entry names '\(first)' and '\(second)' collide under the selected provider's naming rules."
        }
    }
}

struct VaultProviderNamePolicy: Equatable, Sendable {
    let caseSensitivity: VaultProviderCaseSensitivity

    init(caseSensitivity: VaultProviderCaseSensitivity) {
        self.caseSensitivity = caseSensitivity
    }

    func validateNoCollisions(in names: [String]) throws {
        var observedNames: [String: String] = [:]

        for name in names {
            let key = collisionKey(for: name)
            if let existingName = observedNames[key] {
                throw VaultProviderNamePolicyError.collision(
                    first: existingName,
                    second: name
                )
            }
            observedNames[key] = name
        }
    }

    private func collisionKey(for name: String) -> String {
        var key = name.precomposedStringWithCanonicalMapping
        if caseSensitivity == .insensitive {
            key = key.folding(
                options: [.caseInsensitive],
                locale: Locale(identifier: "en_US_POSIX")
            )
        }
        return key.precomposedStringWithCanonicalMapping
    }
}
