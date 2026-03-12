import Testing
@testable import KeyCore

struct CLIParserTests {
    @Test
    func parsesShowCopy() throws {
        let command = try CLIParser.parse(arguments: ["show", "github/personal", "--copy"])
        #expect(command == .show(name: "github/personal", copy: true))
    }

    @Test
    func parsesGeneratedPutOptions() throws {
        let command = try CLIParser.parse(arguments: ["put", "api/token", "--generate", "--length", "48", "--show"])
        #expect(command == .put(name: "api/token", mode: .generated(length: 48, revealMode: .show), force: false))
    }

    @Test
    func rejectsInvalidLength() throws {
        #expect(throws: AppError.invalidLength("Length must be a positive integer.")) {
            try CLIParser.parse(arguments: ["put", "api/token", "--generate", "--length", "0"])
        }
    }

    @Test
    func parsesLs() throws {
        let command = try CLIParser.parse(arguments: ["ls"])
        #expect(command == .list)
    }

    @Test
    func rejectsLegacyListCommand() throws {
        #expect(throws: AppError.usage("Unknown command 'list'.\n\n\(CLIParser.usageText)")) {
            try CLIParser.parse(arguments: ["list"])
        }
    }

    @Test
    func rejectsLegacyGetCommand() throws {
        #expect(throws: AppError.usage("Unknown command 'get'.\n\n\(CLIParser.usageText)")) {
            try CLIParser.parse(arguments: ["get", "github/personal"])
        }
    }

    @Test
    func rejectsCopyWithoutGenerateForPut() throws {
        #expect(throws: AppError.usage("--show and --copy require --generate.\n\n\(CLIParser.usageText)")) {
            try CLIParser.parse(arguments: ["put", "api/token", "--copy"])
        }
    }
}
