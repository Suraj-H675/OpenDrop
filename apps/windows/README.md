# Windows x64 hosted build gate (P1-A passed; Windows 11 runtime pending)

The Windows x64 **source compilation and unsigned MSIX structural gate PASSED**
on GitHub-hosted Windows Server 2022. This is **not** proof of installation on
Windows 11, Share Target activation, Explorer runtime integration or working
file transfers. Both Windows entry points deliberately fail closed until
OpenDrop has a secure transfer queue.

## Verified compilation route: GitHub Actions hosted Windows x64

The owner has **no accessible physical Windows PC**. The reviewed
`.github/workflows/windows-x64-build-only.yml` uses standard **`windows-2022`**
(Windows **Server** 2022 x64) with Visual Studio 2022/MSBuild, MSVC,
Windows SDK 10.0.26100, CMake and .NET 8, as confirmed by actual hosted logs.
Do not silently change project framework or SDK pins simply to use a newer
runner label. Hosted Server CI establishes **compilation/package evidence only**,
not Windows 11 Explorer/Share Target GUI or physical Wi-Fi acceptance.

**Accepted P1-A evidence:** public source commit
[`dca454e987aa00047eb043dff78a6986b28ef5b1`](https://github.com/Suraj-H675/OpenDrop/commit/dca454e987aa00047eb043dff78a6986b28ef5b1)
and [manual Windows build run 43242232569](https://github.com/Suraj-H675/OpenDrop/actions/runs/43242232569)
(`workflow_dispatch`, attempt 1, **completed/success**). Real Windows tooling
compiled the x64 Explorer COM DLL, verified both exact exports, restored pinned
Windows App SDK 2.6.4, compiled WinUI 3, built an **unsigned** x64 MSIX,
unpacked it with MakeAppx, and checked its executable, Explorer DLL, three
**TEST ONLY** images, package identity, Share Target and Explorer COM
registration structure. The four earlier failed workflow runs remain valid
development evidence; passing structural registration checks does not prove
that Windows 11 will activate those registrations at runtime.

The existing workflow retains read-only `contents: read` permissions, a manual
`workflow_dispatch` trigger, no signing secrets, SHA-pinned checkout and
**no artifact upload**. Do not publish `.opendrop-private`, `AGENTS.md`, signing keys,
local evidence, or any debug-only credentials. A successful unsigned package
is **not installable release acceptance**; publisher/certificate identity and
Windows 11 GUI tests require later separate decisions. The specific runner's
installed VS/SDK versions should be logged at job start because images change.

Billing: GitHub documents standard GitHub-hosted runners as free for public
repositories. Recheck repository visibility and billing policies before future
CI authorization. The accepted build used a standard public hosted runner;
no paid runner, artifact upload, release or signing operation was used.

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
Windows SDK/MSIX tooling; XML well-formedness alone is insufficient. The
accepted P1-A hosted run performed these checks successfully. Decide publisher
identity and signing as a
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
