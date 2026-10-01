# Coding standards

These standards apply to new work in SharpHoundCommon. Keep changes focused and follow the style of the file being edited; the repository does not have a single enforced formatter.

## Project boundaries and compatibility

- `src/CommonLib` contains higher-level LDAP, cache, processor, and collection behavior. `src/SharpHoundRPC` contains lower-level Windows RPC, native interop, handle, and registry code. Keep the dependency direction from CommonLib to RPC.
- Both shipping libraries target **.NET Framework 4.7.2** through `Directory.Build.props`. Do not use an API or language feature in library code unless it builds for that target and its configured compiler. The `net8.0` test projects can use newer language features; their syntax is not a compatibility guide for library code.
- Preserve public signatures, serialized output shapes, result and error meanings, and package behavior unless a change deliberately updates that contract. Add a regression test for a behavior change.
- Keep Windows and Active Directory specifics behind the existing interfaces and wrappers so behavior can be tested without a live domain.

## C# style

- Use four spaces for indentation. Match the surrounding file's namespace and brace layout; both end-of-line and next-line braces exist in this repository. Avoid formatting unrelated code.
- Use `PascalCase` for types, public members, and constants; `camelCase` for parameters and locals; and `_camelCase` for private fields. Use names that reflect the AD, LDAP, RPC, or registry concept involved.
- Prefer small methods with explicit inputs and outcomes. Reuse existing interfaces, result types, and helpers instead of introducing a parallel abstraction for the same operation.
- Use `async`/`await` for asynchronous I/O. Propagate cancellation where an API accepts a `CancellationToken`; do not hide cancellation as an ordinary failure.
- Use structured `ILogger` messages with named placeholders. Do not log credentials, tokens, private keys, or raw sensitive directory data.
- In RPC and interop code, make ownership clear. Dispose native handles, buffers, and other disposable resources on success and failure paths; keep conversions and lifetime boundaries close together.
- Add XML documentation when a public API's purpose, parameters, error behavior, or ownership is not clear from its name. Update package READMEs for consumer-facing changes.

## Tests

- Add or update focused xUnit tests in `test/unit` for CommonLib changes and `RPCTest` for RPC changes. Put tests near the existing tests for the affected component.
- Test observable behavior and important failure paths, including null or missing LDAP values, RPC status failures, cancellation, and resource cleanup when relevant. Use the existing mocks and facades for directory, network, and native boundaries.
- Keep routine tests deterministic and independent of a live AD domain or remote host. Avoid timing-sensitive assertions and shared mutable state when practical.
- Use a descriptive test name consistent with neighboring tests; `[Theory]` is useful for related input cases. Do not add tests that only repeat implementation details.

## Validation and review

CI runs on Windows with the .NET 8 SDK. From the repository root, its core sequence is:

```powershell
dotnet restore
dotnet build --no-restore
dotnet test --no-build
```

Run the relevant test project during development, then the full sequence for changes that affect shared code or project configuration. `dotnet test` also generates coverage under `docfx/coverage/` as described in `CONTRIBUTING.md`.

Before review, check for unintended public API changes, compatibility with `net472`, resource leaks, sensitive logging, and unrelated formatting changes. Explain behavior changes and test evidence in the pull request.