// P1-A Windows 11 modern Explorer extension foundation.
// The source enumerates the real IShellItemArray selection, but deliberately
// fails closed until the packaged app's safe IPC/activation path is verified.
// It MUST NOT be registered on a user machine in this batch.
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <ShlObj.h>
#include <ShObjIdl.h>
#include <Shlwapi.h>
#include <atomic>
#include <new>

namespace {
// Identical to the windows.comServer and windows.fileExplorerContextMenus CLSID.
constexpr CLSID kOpenDropCommand =
    {0xAB75604E, 0x1230, 0x4420, {0x82, 0x08, 0x20, 0xFD, 0x88, 0xC8, 0xCB, 0x15}};
std::atomic<long> gObjects{0};
std::atomic<long> gLocks{0};

class OpenDropCommand final : public IExplorerCommand {
    std::atomic<ULONG> refs_{1};
public:
    OpenDropCommand() { ++gObjects; }
    ~OpenDropCommand() { --gObjects; }

    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void **object) override {
        if (!object) return E_POINTER;
        *object = nullptr;
        if (iid == IID_IUnknown || iid == IID_IExplorerCommand) {
            *object = static_cast<IExplorerCommand *>(this);
            AddRef();
            return S_OK;
        }
        return E_NOINTERFACE;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return ++refs_; }
    ULONG STDMETHODCALLTYPE Release() override {
        const ULONG count = --refs_;
        if (!count) delete this;
        return count;
    }

    HRESULT STDMETHODCALLTYPE GetTitle(IShellItemArray *, LPWSTR *title) override {
        return title ? SHStrDupW(L"Share with OpenDrop", title) : E_POINTER;
    }
    HRESULT STDMETHODCALLTYPE GetIcon(IShellItemArray *, LPWSTR *icon) override {
        if (!icon) return E_POINTER;
        *icon = nullptr;
        return E_NOTIMPL; // use package icon when available
    }
    HRESULT STDMETHODCALLTYPE GetToolTip(IShellItemArray *, LPWSTR *tip) override {
        if (!tip) return E_POINTER;
        *tip = nullptr;
        return E_NOTIMPL;
    }
    HRESULT STDMETHODCALLTYPE GetCanonicalName(GUID *commandName) override {
        if (!commandName) return E_POINTER;
        *commandName = kOpenDropCommand;
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE GetState(IShellItemArray *items, BOOL, EXPCMDSTATE *state) override {
        if (!state) return E_POINTER;
        *state = ECS_DISABLED;
        if (!items) return S_OK;
        DWORD count = 0;
        if (FAILED(items->GetCount(&count))) return S_OK;
        // The app handoff is deliberately unavailable until Windows runtime
        // integration is tested: never advertise a working command yet.
        if (count > 0 && count <= 64) *state = ECS_DISABLED;
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE Invoke(IShellItemArray *items, IBindCtx *) override {
        if (!items) return E_INVALIDARG;
        DWORD count = 0;
        HRESULT result = items->GetCount(&count);
        if (FAILED(result)) return result;
        if (!count || count > 64) return E_INVALIDARG;
        // Enumerate local filenames without ever invoking a shell command or
        // interpolating paths into a process command line.
        for (DWORD index = 0; index < count; ++index) {
            IShellItem *item = nullptr;
            result = items->GetItemAt(index, &item);
            if (FAILED(result) || !item) return FAILED(result) ? result : E_FAIL;
            SFGAOF attrs = SFGAO_FILESYSTEM | SFGAO_FOLDER;
            result = item->GetAttributes(attrs, &attrs);
            if (FAILED(result) || !(attrs & SFGAO_FILESYSTEM) || (attrs & SFGAO_FOLDER)) {
                item->Release();
                return E_INVALIDARG;
            }
            PWSTR absolute = nullptr;
            result = item->GetDisplayName(SIGDN_FILESYSPATH, &absolute);
            if (absolute) CoTaskMemFree(absolute);
            item->Release();
            if (FAILED(result)) return result;
        }
        // The actual WinUI/agent IPC handoff and package identity are NOT
        // implemented or Windows-validated. Never pretend the share queued.
        return HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED);
    }
    HRESULT STDMETHODCALLTYPE GetFlags(EXPCMDFLAGS *flags) override {
        if (!flags) return E_POINTER;
        *flags = ECF_DEFAULT;
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE EnumSubCommands(IEnumExplorerCommand **commands) override {
        if (!commands) return E_POINTER;
        *commands = nullptr;
        return E_NOTIMPL;
    }
};

class CommandFactory final : public IClassFactory {
    std::atomic<ULONG> refs_{1};
public:
    CommandFactory() { ++gObjects; }
    ~CommandFactory() { --gObjects; }
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void **object) override {
        if (!object) return E_POINTER;
        *object = nullptr;
        if (iid == IID_IUnknown || iid == IID_IClassFactory) {
            *object = static_cast<IClassFactory *>(this);
            AddRef();
            return S_OK;
        }
        return E_NOINTERFACE;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return ++refs_; }
    ULONG STDMETHODCALLTYPE Release() override {
        const ULONG count = --refs_;
        if (!count) delete this;
        return count;
    }
    HRESULT STDMETHODCALLTYPE CreateInstance(IUnknown *outer, REFIID iid, void **object) override {
        if (outer) return CLASS_E_NOAGGREGATION;
        if (!object) return E_POINTER;
        *object = nullptr;
        auto *command = new (std::nothrow) OpenDropCommand();
        if (!command) return E_OUTOFMEMORY;
        const HRESULT hr = command->QueryInterface(iid, object);
        command->Release();
        return hr;
    }
    HRESULT STDMETHODCALLTYPE LockServer(BOOL lock) override {
        if (lock) ++gLocks;
        else --gLocks;
        return S_OK;
    }
};
} // namespace

extern "C" __declspec(dllexport) HRESULT __stdcall DllGetClassObject(REFCLSID clsid, REFIID iid, LPVOID *object) {
    if (clsid != kOpenDropCommand) return CLASS_E_CLASSNOTAVAILABLE;
    if (!object) return E_POINTER;
    auto *factory = new (std::nothrow) CommandFactory();
    if (!factory) return E_OUTOFMEMORY;
    const HRESULT result = factory->QueryInterface(iid, object);
    factory->Release();
    return result;
}
extern "C" __declspec(dllexport) HRESULT __stdcall DllCanUnloadNow() {
    return gObjects.load() == 0 && gLocks.load() == 0 ? S_OK : S_FALSE;
}
