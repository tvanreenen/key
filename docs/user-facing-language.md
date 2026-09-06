# User-facing language

Key's CLI, authentication prompts, dashboard, completions, and user documentation should explain the same actions in the same terms. This guide applies to human-facing text, not storage schemas or identifiers used by scripts.

## Explain the outcome

Say what happened, what it means for the user, and the next safe action. Prefer "Key will use this vault for future commands on this Mac" to "selected the verified vault." Say "unlock the vault" instead of "warm the helper session." Use "Mac" for the computers currently supported by enrollment, and "background service" when explaining Key Agent to users.

Use "vault" in routine commands. Introduce "older Keychain-backed format" or "device-enrolled vault" when the distinction affects a choice. Keep format numbers in compatibility errors, migration explanations, verbose diagnostics, and technical references. Do not confuse a vault's format with the installed application's version.

## Describe only what Key knows

Missing files do not prove that synchronization is progressing. Say that files are unavailable, then suggest checking synchronization. A failed operation may have created files or local credentials; do not promise that nothing changed unless that specific path guarantees it. After successful setup followed by a delayed service restart, explain that setup completed and direct the user to status, not another setup attempt.

Security failures need specific wording. Keep the distinction between ordinary conflicting edits, unavailable files, failed verification, and conflicting device access. Do not prescribe deletion, init, or an unsupported recovery command as a way around verification. If no safe automatic continuation exists, say the state needs investigation and ask the user to keep vault files and local records intact.

## Explain authorization and loss

Authentication prompts should name the action being authorized. Explain consequential effects before the prompt, including creating access credentials, changing the encryption key, replacing a Mac's old credentials, or removing access. Do not hide these effects behind implementation terms such as "key epoch" or "guarded publication."

Removing a Mac's access cannot erase secrets or older data it already obtained. A backup of the vault folder alone cannot restore access if every enrolled Mac is lost. Keep those limitations visible where users make the relevant decisions. Do not imply that a password, hardware-key recovery method, or support override exists before it is implemented and qualified.

## Preserve command contracts

Human explanations may change, but keep JSON field names, machine error codes, IDs, exit statuses, and secret output stable. Do not add progress or success text to secret stdout. Preserve recognition of older CLI diagnostic messages when updating the dashboard. Error messages and authentication prompts must never include secret values or protected key material.

Top-level help should support discovery. Command help should give syntax, examples, effects, and relevant limits. Test both `key help <command>` and `key <command> --help` without contacting the background service or creating configuration. Keep help, completions, and documentation aligned. Document newly added behavior as unreleased until it ships.

Write documentation paragraphs on one logical line. Use line breaks for Markdown structure and code examples, not a fixed prose column width.
