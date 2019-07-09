#ifndef TOPMOST_HPP
#define TOPMOST_HPP

#include <Windows.h>

#include <chrono>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <thread>

namespace TopMost
{
using namespace std::chrono_literals;

struct MakeTop {
    DWORD pid;
    std::set<HWND> children;
    std::thread setter;

    bool runnable;
    bool hook;
    bool log;

    static constexpr std::chrono::seconds term = 1s;

    static MakeTop CurrentProc(bool runThread = true, bool hook = false, bool log = false) {
        return MakeTop(GetCurrentProcessId(), runThread, hook, log);
    }

    static std::optional<MakeTop> ByName(std::string const& title,
                                         bool runThread = true,
                                         bool hook = false,
                                         bool log = false) {
        HWND hWnd = FindWindowA(NULL, title.c_str());
        if (hWnd == NULL) {
            return std::nullopt;
        }

        DWORD dwPid;
        if (!GetWindowThreadProcessId(hWnd, &dwPid)) {
            return std::nullopt;
        }

        return std::make_optional<MakeTop>(dwPid, runThread, hook, log);
    }

    MakeTop() : pid(0), children(), setter(), runnable(false), hook(false), log(false) {
        // Do Nothing
    }

    MakeTop(DWORD pid, bool runThread = true, bool hook = false, bool log = false) : 
        pid(pid), children(GetChildWindowHandles(pid)), setter(),
        runnable(false), hook(hook), log(log)
    {
        SetChildWindowsTopMost();
        if (runThread) {
            RunThread();
        }
    }

    ~MakeTop() {
        Stop();
    }

    MakeTop(MakeTop&& other) :
        pid(other.pid), children(std::move(other.children)), setter(std::move(other.setter)),
        runnable(other.runnable), hook(other.hook)
    {
        // Do Nothing
    }

    MakeTop(MakeTop const&) = delete;

    MakeTop& operator=(MakeTop&& other) {
        pid = other.pid;
        children = std::move(other.children);
        setter = std::move(other.setter);
        runnable = other.runnable;
        hook = other.hook;
        return *this;
    }

    MakeTop& operator=(MakeTop const&) = delete;

    void RunThread() {
        if (log) {
            logger() << "Start thread" << std::endl;
        }

        runnable = true;
        setter = std::thread([this] {
            while (runnable) {
                std::this_thread::sleep_for(term);

                UpdateChildWindows();
                HWND hWnd = GetTopWindow(NULL);
                static std::set<std::string> blacklist = {
                    "MSCTFIME UI", "Default IME", ""
                };

                while (hWnd != NULL) {
                    if (children.find(hWnd) != children.end()) {
                        break;
                    }

                    constexpr size_t bufsize = 1024;
                    char text[bufsize] = { 0, };
                    int read = GetWindowTextA(hWnd, text, bufsize);

                    if (blacklist.find(text) == blacklist.end()) {
                        if (log) {
                            logger() << "other topmost app found (name: " << text << ')' << std::endl;
                        }

                        SetChildWindowsTopMost();
                        if (hook) {
                            if (HookSetWindowPos(hWnd)) {
                                logger() << "hook success" << std::endl;
                            }
                            else {
                                logger() << "hook failure" << std::endl;
                            }
                        }
                        break;
                    }

                    hWnd = GetWindow(hWnd, GW_HWNDNEXT);
                }
            }
        });
    }

    void Stop() {
        if (runnable) {
            runnable = false;
            setter.join();
        }
    }

    void SetChildWindowsTopMost() {
        for (HWND hWnd : children) {
            SetTopMost(hWnd);
        }
    }

    void UpdateChildWindows() {
        children = GetChildWindowHandles(pid);
    }

    std::ostream& logger() {
        return (std::cout << "[*] TopMost : ");
    }

    static void SetTopMost(HWND hWnd) {
        SetWindowPos(hWnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
    }

    static std::set<HWND> GetChildWindowHandles(DWORD pid) {
        std::pair<DWORD, std::set<HWND>> pair;
        pair.first = pid;

        BOOL bResult = EnumWindows([](HWND hWnd, LPARAM lpParam) {
            DWORD dwPid;
            auto param = reinterpret_cast<std::pair<DWORD, std::set<HWND>>*>(lpParam);
            if (GetWindowThreadProcessId(hWnd, &dwPid) && dwPid == param->first) {
                param->second.insert(hWnd);
            }
            return TRUE;
        }, reinterpret_cast<LPARAM>(&pair));

        return pair.second;
    }

    static bool HookSetWindowPos(HWND hWnd) {
        DWORD dwPid;
        if (!GetWindowThreadProcessId(hWnd, &dwPid)) {
            return false;
        }

        HANDLE hProcess = OpenProcess(PROCESS_VM_OPERATION, FALSE, dwPid);
        if (hProcess == INVALID_HANDLE_VALUE) {
            return false;
        }

        HMODULE hUser32 = GetModuleHandleW(L"User32.lib");
        FARPROC lpSetWindowPos = GetProcAddress(hUser32, "SetWindowPos");

        // mov eax, 1; ret
        static BYTE opcode[] = { 0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3 };

        DWORD flOldProtect;
        if (!VirtualProtectEx(hProcess, lpSetWindowPos, sizeof(opcode), 
                              PAGE_EXECUTE_READWRITE, &flOldProtect))
        {
            CloseHandle(hProcess);
            return false;
        }

        SIZE_T written;
        if (!WriteProcessMemory(hProcess, lpSetWindowPos, opcode, sizeof(opcode), &written)) {
            CloseHandle(hProcess);
            return false;
        }

        VirtualProtectEx(hProcess, lpSetWindowPos, sizeof(opcode), flOldProtect, &flOldProtect);
        CloseHandle(hProcess);

        return true;
    }
};
}

#endif