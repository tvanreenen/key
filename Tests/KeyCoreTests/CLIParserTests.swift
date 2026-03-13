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
        let command = try CLIParser.parse(arguments: ["copy", "src/token", "dst/token", "--force"])
        #expect(command == .copy(source: "src/token", destination: "dst/token", force: true))
    }

    @Test
    func parsesEdit() throws {
        let command = try CLIParser.parse(arguments: ["edit", "api/token"])
        #expect(command == .edit(name: "api/token"))
    }

    @Test
    func parsesMoveWithForce() throws {
        let command = try CLIParser.parse(arguments: ["move", "src/token", "dst/token", "--force"])
        #expect(command == .move(source: "src/token", destination: "dst/token", force: true))
    }

    @Test
    func parsesRemoveWithForce() throws {
        let command = try CLIParser.parse(arguments: ["remove", "src/token", "--force"])
        #expect(command == .remove(name: "src/token", force: true))
    }

    @Test
    func parsesList() throws {
        let command = try CLIParser.parse(arguments: ["list"])
        #expect(command == .list)
    }

    @Test
    func parsesCopyAlias() throws {
        let command = try CLIParser.parse(arguments: ["cp", "src/token", "dst/token"])
        #expect(command == .copy(source: "src/token", destination: "dst/token", force: false))
    }

    @Test
    func parsesMoveAlias() throws {
        let command = try CLIParser.parse(arguments: ["mv", "src/token", "dst/token"])
        #expect(command == .move(source: "src/token", destination: "dst/token", force: false))
    }

    @Test
    func parsesRemoveAlias() throws {
        let command = try CLIParser.parse(arguments: ["rm", "src/token"])
        #expect(command == .remove(name: "src/token", force: false))
    }

    @Test
    func parsesListAlias() throws {
        let command = try CLIParser.parse(arguments: ["ls"])
        #expect(command == .list)
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
        #expect(throws: AppError.usage("Missing destination entry name for copy.\n\n\(CLIParser.usageText)")) {
            try CLIParser.parse(arguments: ["copy", "src/token"])
        }
    }

    @Test
    func rejectsMoveWithoutDestination() throws {
        #expect(throws: AppError.usage("Missing destination entry name for move.\n\n\(CLIParser.usageText)")) {
            try CLIParser.parse(arguments: ["move", "src/token"])
        }
    }

    @Test
    func rejectsRemoveWithoutName() throws {
        #expect(throws: AppError.usage("Missing entry name for remove.\n\n\(CLIParser.usageText)")) {
            try CLIParser.parse(arguments: ["remove"])
        }
    }
}
