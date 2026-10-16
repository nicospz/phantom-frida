# Injector handshake diagnostics

Enabled only by `--injector-diagnostics`, alongside the existing write-path
diagnostics. Source contracts target frida-core commit
`0e1a53ba7ab7615e6c8cc0cf1ee4fc45ab7d0722` (17.16.4). The test fixtures contain
the corresponding loader/header source and the relevant monitor excerpt.

The injector prints received message types and monotonic microseconds since its
monitor started. An incomplete handshake prints the last type and the read stage.
An I/O exception prints only its numeric domain/code, not arbitrary exception text.
The existing loader error handling remains intact.

| Type | Meaning |
| --- | --- |
| 0 | HELLO (loader worker started communicating) |
| 1 | READY |
| 2 | ACK (injector-to-loader, not a received monitor event) |
| 3 | BYE |
| 4 | ERROR_DLOPEN |
| 5 | ERROR_DLSYM |
| 6 | Enter agent-library descriptor receive |
| 7 | Agent-library descriptor received |
| 8 | Agent-library descriptor receive failed |
| 9 | Enter dlopen |
| 10 | dlopen succeeded |
| 11 | Enter dlsym |
| 12 | dlsym succeeded |
| 13 | Enter control descriptor receive |
| 14 | Control descriptor receive returned (absence is permitted) |
| 15 | ACK received |
| 16 | Enter agent entrypoint |
| 17 | Agent entrypoint returned |
| 18 | Enter cleanup |
| 255 | No message type received yet |

New loader messages are single-byte, nonblocking, best-effort sends. They contain
no script arguments, account data or memory contents. A dropped record is not
proof that its stage did not run. Existing message numbers and payloads are
unchanged; the paired monitor ignores diagnostic types after logging them.
No SELinux policy, tracing or loader success/failure decisions are changed by
this diagnostic extension.

Tests compile and execute the actual patched loader against mocked libc calls:
success, failed descriptor receipt, dlopen failure, dlsym failure and dropped
diagnostic sends. Cleanup and entrypoint outcomes must remain unchanged. Tests
also reject source drift and check that C and Vala message numbers agree.
