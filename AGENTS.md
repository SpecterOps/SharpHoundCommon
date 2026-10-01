# Repository guide for coding agents

Read `coding_standards.md` and `CONTRIBUTING.md` before changing code. Treat this file as a practical map of the repository, not as a substitute for inspecting the affected component.

## Repository map

- `src/CommonLib/`: `SharpHoundCommonLib`, the higher-level library for LDAP resolution, caching, processors, metrics, and collection support.
- `src/SharpHoundRPC/`: `SharpHoundRPC`, the lower-level Windows RPC, native interop, handle, and registry library. CommonLib references this project.
- `test/unit/`: xUnit tests for CommonLib, including mocks and facades.
- `RPCTest/`: xUnit tests for SharpHoundRPC.
- `docfx/`: documentation project and generated coverage output.
- `.github/workflows/build-and-test.yml`: authoritative CI build and test sequence.

The two shipping projects target `net472` via `Directory.Build.props`; both test projects target `net8.0`. The root README's older prerequisite text does not override the project files. Windows is the CI platform and the code uses Windows and Active Directory APIs.

## Working on a change

1. Inspect the affected project, nearby implementation and tests, and any relevant public contract before editing.
2. Keep changes scoped. Follow the existing style in each file; do not reformat unrelated code or change target frameworks, dependencies, package metadata, or generated files without a task reason.
3. Put high-level behavior in CommonLib and native/RPC details in SharpHoundRPC. Preserve existing result, error, cancellation, and handle ownership behavior unless the task calls for changing it.
4. Add focused tests for behavior changes using local mocks or facades. Do not require a live domain, credentials, or external hosts for routine tests.
5. Run the relevant test project, then the CI sequence when shared behavior or build configuration changes. Report commands run, failures, and any environment limitation accurately.
6. Update relevant README or API documentation when a consumer-facing contract changes.

## Commands

Run from the repository root on Windows with the .NET 8 SDK:

```powershell
dotnet restore
dotnet build --no-restore
dotnet test --no-build
```

For a focused check, use `dotnet test test/unit/CommonLibTest.csproj` or `dotnet test RPCTest/RPCTest.csproj`. `dotnet test` produces coverage files under `docfx/coverage/`.

## Workspace care

- Inspect `git status` before and after changes. Preserve user edits and untracked files.
- Do not commit generated coverage, `bin/`, or `obj/` output.
- Do not put secrets, credentials, or sensitive collected directory data into code, tests, logs, or documentation.
- If the requested change needs a real AD environment or Windows-only behavior that cannot be exercised locally, use the available unit tests and state the remaining validation gap.