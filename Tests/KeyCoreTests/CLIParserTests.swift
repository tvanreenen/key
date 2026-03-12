import Testing
@testable import KeyCore

struct CLIParserTests {
    @Test
    func parsesShowCopy() throws {
        let command = try CLIParser.parse(arguments: ["show", "github/personal", "--copy"])
        #expect(command == .show(name: "github/personal", copy: true))
    }

    @Test
    func parsesGeneratedAddOptions() throws {
        let command = try CLIParser.parse(arguments: ["add", "api/token", "--generate", "--length", "48"])
        #expect(command == .add(name: "api/token", mode: .generated(length: 48, revealMode: .none)))
    }

    @Test
    func parsesGeneratedEditOptions() throws {
        let command = try CLIParser.parse(arguments: ["edit", "api/token", "--generate", "--length", "48"])
        #expect(command == .edit(name: "api/token", mode: .generated(length: 48, revealMode: .none)))
    }

    @Test
    func parsesCopyWithForce() throws {
        let command = try CLIParser.parse(arguments: ["cp", "src/token", "dst/token", "--force"])
        #expect(command == .copy(source: "src/token", destination: "dst/token", force: true))
    }

    @Test
    func rejectsInvalidLength() throws {
        #expect(throws: AppError.invalidLength("Length must be a positive integer.")) {
            try CLIParser.parse(arguments: ["add", "api/token", "--generate", "--length", "0"])
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
    func rejectsLegacyPutCommand() throws {
        #expect(throws: AppError.usage("Unknown command 'put'.\n\n\(CLIParser.usageText)")) {
            try CLIParser.parse(arguments: ["put", "api/token"])
        }
    }

    @Test
    func rejectsUnsupportedAddOptions() throws {
        #expect(throws: AppError.usage("Unknown option '--copy' for add.\n\n\(CLIParser.usageText)")) {
            try CLIParser.parse(arguments: ["add", "api/token", "--copy"])
        }
    }

    @Test
    func rejectsUnsupportedEditOptions() throws {
        #expect(throws: AppError.usage("Unknown option '--copy' for edit.\n\n\(CLIParser.usageText)")) {
            try CLIParser.parse(arguments: ["edit", "api/token", "--copy"])
        }
    }

    @Test
    func rejectsCopyWithoutDestination() throws {
        #expect(throws: AppError.usage("Missing destination entry name for cp.\n\n\(CLIParser.usageText)")) {
            try CLIParser.parse(arguments: ["cp", "src/token"])
        }
    }
}
