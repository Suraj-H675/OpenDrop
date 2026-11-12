# Windows 11 x64 native build gate (P1-A)

This is **source/build preparation only**, not proof of a Windows build, MSIX
installation, Share Target activation, or Explorer integration. Both Windows
entry points deliberately fail closed until OpenDrop has a secure transfer queue.

## First compilation route: GitHub Actions hosted Windows x64 (not executed)

The owner has **no accessible physical Windows PC**. The ready-to-review
`.github/workflows/windows-x64-build-only.yml` uses standard **`windows-2022`**
(Windows **Server** 2022 x64), deliberately not `windows-2025`: as of November
2026 GitHub's documented `windows-2025` label routes to a **Visual Studio
2026** image, while the existing CMake generator and COM source setup use
**Visual Studio 2022**. The Windows Server 2022 inventory includes VS2022,
MSVC, Windows SDK 10.0.26100, CMake and .NET8. Do not silently change project
framework or SDK pins simply to use the newer runner label.
This can establish **compilation/package evidence only**; hosted Server CI is
not a Windows 11 Explorer/Share Target GUI acceptance test and cannot verify
physical Wi-Fi sharing. No GitHub Actions workflow has been created or run.

When separately authorized to commit/push **production-only** sources and add
CI, use read-only `contents: read` permissions, a manual `workflow_dispatch`
trigger for the initial gate, no signing secrets, and `windows-2022` with
VS2022/MSBuild setup. The first workflow uses SHA-pinned checkout and does
**not upload any artifact**. It compiles CMake x64 COM, restores pinned WinUI3,
builds an **unsigned** MSIX and unpacks it with MakeAppx for entry/registration
checks. Do not publish `.opendrop-private`, `AGENTS.md`, signing keys,
local evidence, or any debug-only credentials. A successful unsigned package
is **not installable release acceptance**; publisher/certificate identity and
Windows 11 GUI tests require later separate decisions. The specific runner's
installed VS/SDK versions should be logged at job start because images change.

Billing: GitHub currently lists standard Windows 2-core x64 compute at
**$0.010 per rounded job-minute** for chargeable usage; eligible private-repo
usage draws from the account's monthly included compute allowance, while
standard GitHub-hosted runners are free for public repositories. Check the
actual repo visibility, current budget and billing limits before authorizing
the first run. No CI, upload, paid service or signing operation was used here.

## Build prerequisites (hosted Server CI or later authorized Windows 11 host)

- An approved **Windows x64 build environment**; Visual Studio 2022 MSBuild and MSVC
  with Desktop C++/CMake support, .NET **8 SDK** and Windows SDK **10.0.22000.0
  or later** (including MSIX/MakeAppx and signing tools).
- Windows App SDK / WinUI 3 build dependencies, including NuGet restore access
  or an **already provisioned** compatible offline package cache for the pinned
  `Microsoft.WindowsAppSDK` **2.6.4**. Do not silently upgrade its version.
- Three original neutral grayscale **TEST ONLY** PNG artwork files now exist
  in `packaging/Assets/` with required dimensions. These are **strictly
  compilation placeholders**, not approved logo, branding, release art or
  Round03/04 UI. See `packaging/Assets/README.md` for exact hashes and
  prohibitions. They must be packaged as `Assets/<filename>` at the MSIX root;
  replacing them with approved product artwork is a later mandatory release
  gate.
- A package publisher/certificate decision. `CN=OpenDropDevelopment` in the
  manifest is **illustrative only**, not a real signing identity. The eventual
  certificate subject must match the actual package Publisher and the signing
  chain must be trusted where the package is installed. No certificate or key
  belongs in Git. Runtime deployment of the framework-dependent Windows App SDK
  is a later, separately authorized test/install concern.

## Ordered build procedure on the approved Windows environment

From the checkout root in a VS 2022 Developer PowerShell (once the above
dependencies are present):

```powershell
cmake -S .\apps\windows\explorer -B .\apps\windows\explorer\build -G "Visual Studio 17 2022" -A x64
cmake --build .\apps\windows\explorer\build --config Release
Test-Path .\apps\windows\explorer\build\Release\OpenDropExplorer.dll

msbuild .\apps\windows\OpenDrop.Windows\OpenDrop.Windows.csproj /t:Restore /p:Platform=x64 /p:RuntimeIdentifier=win-x64
msbuild .\apps\windows\OpenDrop.Windows\OpenDrop.Windows.csproj /t:Build /p:Configuration=Release /p:Platform=x64 /p:RuntimeIdentifier=win-x64 /p:GenerateAppxPackageOnBuild=true /p:AppxBundle=Never /p:AppxPackageSigningEnabled=false
```

Do **not** proceed after a failed build or missing DLL. The C# MSBuild project
now includes the **prebuilt x64** Explorer DLL as `OpenDropExplorer.dll` at the
package root and includes all three assets at their Manifest paths; it fails
early when any of these files is absent. The DLL is deliberately compiled by
CMake first, not simulated by C# or an unchecked post-build copy. The path can
be overridden with `/p:OpenDropExplorerDll=<absolute-path>` if the reviewed
Windows build layout differs.

On the Windows runner, inspect the actual `.msix` with Windows SDK `MakeAppx`:
confirm root `OpenDropExplorer.dll`, `Assets/*`, application executable, the
`windows.shareTarget`, `windows.comServer` and `windows.fileExplorerContextMenus`
registrations, and the CLSID agreement. Validate the manifest with the real
Windows SDK/MSIX tooling; XML well-formedness alone is insufficient. Confirm
that the Windows App SDK version, WinUI APIs and package project build cleanly;
this is **not yet demonstrated**. Decide publisher identity and signing as a
separate gate before any authorized install. Windows Share Target and Explorer
entry points require later *owner-operated* GUI testing.

The C# Share Target uses packaged `AppInstance.GetCurrent().GetActivatedEventArgs()`
and a granted `ShareOperation`/`IStorageFile`. The native COM DLL implements
`IExplorerCommand`, checks the real selected `IShellItemArray`, and returns
`ERROR_NOT_SUPPORTED` until the app handoff exists. Its CLSID is registered by
the manifest for modern primary Explorer context menus. No network transfer or
receiver completion is claimed by either entry point.

Official references: [Share Target](https://learn.microsoft.com/windows/apps/develop/windows-integration/receive-shared-data),
[packaged Explorer integration](https://learn.microsoft.com/windows/apps/desktop/modernize/integrate-packaged-app-with-file-explorer),
[GitHub runner images](https://github.com/actions/runner-images),
[Windows Server 2022 installed tools](https://github.com/actions/runner-images/blob/main/images/windows/Windows2022-Readme.md),
[GitHub hosted-runner pricing](https://docs.github.com/en/billing/reference/actions-runner-pricing).
