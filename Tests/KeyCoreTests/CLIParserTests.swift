import Testing
@testable import KeyCore

struct CLIParserTests {
    @Test
    func parsesGetCopy() throws {
        let command = try CLIParser.parse(arguments: ["get", "github/personal", "--copy"])
        #expect(command == .get(name: "github/personal", copy: true))
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
    func parsesList() throws {
        let command = try CLIParser.parse(arguments: ["list"])
        #expect(command == .list)
    }

    @Test
    func rejectsCopyWithoutGenerateForPut() throws {
        #expect(throws: AppError.usage("--show and --copy require --generate.\n\n\(CLIParser.usageText)")) {
            try CLIParser.parse(arguments: ["put", "api/token", "--copy"])
        }
    }
}
