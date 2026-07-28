import Testing
@testable import KeyCore

struct VaultProviderNamePolicyTests {
    @Test
    func caseInsensitiveProviderRejectsCaseCollisions() {
        let policy = VaultProviderNamePolicy(caseSensitivity: .insensitive)

        #expect(throws: VaultProviderNamePolicyError.collision(
            first: "Accounts/GitHub",
            second: "accounts/github"
        )) {
            try policy.validateNoCollisions(in: [
                "Accounts/GitHub",
                "accounts/github"
            ])
        }
    }

    @Test
    func caseSensitiveProviderAllowsDistinctCase() throws {
        let policy = VaultProviderNamePolicy(caseSensitivity: .sensitive)

        try policy.validateNoCollisions(in: [
            "Accounts/GitHub",
            "accounts/github"
        ])
    }

    @Test
    func everyProviderRejectsCanonicalUnicodeCollisions() {
        for caseSensitivity in [
            VaultProviderCaseSensitivity.sensitive,
            .insensitive
        ] {
            let policy = VaultProviderNamePolicy(
                caseSensitivity: caseSensitivity
            )
            #expect(throws: VaultProviderNamePolicyError.collision(
                first: "Caf\u{00E9}",
                second: "Cafe\u{0301}"
            )) {
                try policy.validateNoCollisions(in: [
                    "Caf\u{00E9}",
                    "Cafe\u{0301}"
                ])
            }
        }
    }
}
