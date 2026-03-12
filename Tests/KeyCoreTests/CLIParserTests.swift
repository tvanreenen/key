import Testing
@testable import KeyCore

struct CLIParserTests {
    @Test
    func parsesShowCopy() throws {
        let command = try CLIParser.parse(arguments: ["show", "github/personal", "--copy"])
        #expect(command == .show(name: "github/personal", copy: true))
    }

    @Test
    func parsesAdd() throws {
        let command = try CLIParser.parse(arguments: ["add", "api/token"])
        #expect(command == .add(name: "api/token"))
    }

    @Test
    func parsesCopyWithForce() throws {
        let command = try CLIParser.parse(arguments: ["cp", "src/token", "dst/token", "--force"])
        #expect(command == .copy(source: "src/token", destination: "dst/token", force: true))
    }

    @Test
    func parsesEdit() throws {
        let command = try CLIParser.parse(arguments: ["edit", "api/token"])
        #expect(command == .edit(name: "api/token"))
    }

    @Test
    func parsesMoveWithForce() throws {
        let command = try CLIParser.parse(arguments: ["mv", "src/token", "dst/token", "--force"])
        #expect(command == .move(source: "src/token", destination: "dst/token", force: true))
    }

    @Test
    func parsesRemoveWithForce() throws {
        let command = try CLIParser.parse(arguments: ["rm", "src/token", "--force"])
        #expect(command == .remove(name: "src/token", force: true))
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
        #expect(throws: AppError.usage("Unknown option '--generate' for add.\n\n\(CLIParser.usageText)")) {
            try CLIParser.parse(arguments: ["add", "api/token", "--generate"])
        }
    }

    @Test
    func rejectsUnsupportedEditOptions() throws {
        #expect(throws: AppError.usage("Unknown option '--generate' for edit.\n\n\(CLIParser.usageText)")) {
            try CLIParser.parse(arguments: ["edit", "api/token", "--generate"])
        }
    }

    @Test
    func rejectsCopyWithoutDestination() throws {
        #expect(throws: AppError.usage("Missing destination entry name for cp.\n\n\(CLIParser.usageText)")) {
            try CLIParser.parse(arguments: ["cp", "src/token"])
        }
    }

    @Test
    func rejectsMoveWithoutDestination() throws {
        #expect(throws: AppError.usage("Missing destination entry name for mv.\n\n\(CLIParser.usageText)")) {
            try CLIParser.parse(arguments: ["mv", "src/token"])
        }
    }

    @Test
    func rejectsRemoveWithoutName() throws {
        #expect(throws: AppError.usage("Missing entry name for rm.\n\n\(CLIParser.usageText)")) {
            try CLIParser.parse(arguments: ["rm"])
        }
    }
}
