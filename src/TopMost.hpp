#ifndef TOPMOST_HPP
#define TOPMOST_HPP

#include <Windows.h>

#include <chrono>
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

    static std::unique_ptr<MakeTop> CurrentProc(bool runThread = true, bool hook = false, bool log = false) {
        return std::make_unique<MakeTop>(GetCurrentProcessId(), runThread, hook, log);
    }

    static std::unique_ptr<MakeTop> ByName(std::string const& title,
                                           bool runThread = true,
                                           bool hook = false,
                                           bool log = false)
    {
        HWND hWnd = FindWindowA(NULL, title.c_str());
        if (hWnd == NULL) {
            return nullptr;
        }

        DWORD dwPid;
        if (!GetWindowThreadProcessId(hWnd, &dwPid)) {
            return nullptr;
        }

        return std::make_unique<MakeTop>(dwPid, runThread, hook, log);
    }

    MakeTop(DWORD pid, bool runThread = true, bool hook = false, bool log = false) : 
        pid(pid), children(GetChildWindowHandles(pid)), setter(),
        runnable(false), hook(hook), log(log)
    {
        SetChildWindowsTopMost();
        if (runThread) {
            RunThread();
        } else {
            runnable = true;
            Loop();
        }
    }

    ~MakeTop() {
        Stop();
    }

    MakeTop(MakeTop&& other) = delete;
    MakeTop(MakeTop const&) = delete;
    MakeTop& operator=(MakeTop&& other) = delete;
    MakeTop& operator=(MakeTop const&) = delete;

    void RunThread() {
        if (log) {
            logger() << "Start thread" << std::endl;
        }

        runnable = true;
        setter = std::thread([this] { Loop(); });
    }

    void Loop() {
        if (log) {
            logger() << "Start Loop" << std::endl;
        }

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
                        if (HookSetWindowPos(hWnd, log)) {
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

    static bool HookSetWindowPos(HWND hWnd, bool log = false) {
        DWORD dwPid;
        if (!GetWindowThreadProcessId(hWnd, &dwPid)) {
            if (log) {
                std::cout << "[Hook] GetWindowThreadProcessId fail" << std::endl;
            }
            return false;
        }
        return HookSetWindowPos(dwPid, log);
    }

    static bool HookSetWindowPos(DWORD dwPid, bool log = false) {
        HANDLE hProcess = OpenProcess(PROCESS_VM_OPERATION, FALSE, dwPid);
        if (hProcess == INVALID_HANDLE_VALUE) {
            if (log) {
                std::cout << "[Hook] OpenProcess fail" << std::endl;
            }
            return false;
        }

        HMODULE hUser32 = GetModuleHandleW(L"User32.dll");
        FARPROC lpSetWindowPos = GetProcAddress(hUser32, "SetWindowPos");
        if (hUser32 == NULL || lpSetWindowPos == NULL) {
            if (log) {
                std::cout << "[HOOK] GetProcAddress fail" << std::endl;
            }
            return false;
        }

        // mov eax, 1; ret
        static BYTE opcode[] = { 0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3 };

        DWORD flOldProtect;
        if (!VirtualProtectEx(hProcess, lpSetWindowPos, sizeof(opcode), 
                              PAGE_EXECUTE_READWRITE, &flOldProtect))
        {
            if (log) {
                std::cout << "[Hook] VirtualProtectEx fail " << GetLastError() << std::endl;
            }
            CloseHandle(hProcess);
            return false;
        }

        SIZE_T written;
        if (!WriteProcessMemory(hProcess, lpSetWindowPos, opcode, sizeof(opcode), &written)) {
            if (log) {
                std::cout << "[Hook] WriteProcessMemory fail " << GetLastError() << std::endl;
            }
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