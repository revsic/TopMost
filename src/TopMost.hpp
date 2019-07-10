// Copyright (C) 2019 Youngjoong Kim

#ifndef TOPMOST_HPP
#define TOPMOST_HPP

#include <Windows.h>

#include <iostream>
#include <chrono>
#include <set>
#include <stdexcept>
#include <string>
#include <thread>

namespace TopMost
{
using namespace std::chrono_literals;

//!
//! \brief MakeTop class.
//!
//! This class makes target process as topmost window.
//!
struct MakeTop {
    DWORD pid;
    std::set<HWND> children;
    std::thread setter;

    bool runnable;
    bool runThread;
    bool hook;
    bool log;

    static constexpr std::chrono::seconds term = 1s;

    //! Makes current process as topmost.
    //! \param runThread A flag for running thread or just inplace loop.
    //! \param hook (experimental) A flag for hooking other process to avoid the blinking of two topmost processes.
    //! \param log A flag for logging process status.
    //! \return Constructed MakeTop structure.
    static std::unique_ptr<MakeTop> CurrentProc(bool runThread = true, bool hook = false, bool log = false) {
        return std::make_unique<MakeTop>(GetCurrentProcessId(), runThread, hook, log);
    }

    //! Find process by its title and make topmost.
    //! \param title The title of the window for finding process.
    //! \param runThread A flag for running thread or just inplace loop.
    //! \param hook (experimental) A flag for hooking other process to avoid the blinking of two topmost processes.
    //! \param log A flag for logging process status.
    //! \return Constructed MakeTop structure.
    static std::unique_ptr<MakeTop> ByName(std::string const& title,
                                           bool runThread = true,
                                           bool hook = false,
                                           bool log = false)
    {
        // find window with title
        HWND hWnd = FindWindowA(NULL, title.c_str());
        if (hWnd == NULL) {
            return nullptr;
        }

        // get pid from window handler
        DWORD dwPid;
        if (!GetWindowThreadProcessId(hWnd, &dwPid)) {
            return nullptr;
        }

        return std::make_unique<MakeTop>(dwPid, runThread, hook, log);
    }

    //! Constructs MakeTop with given \p pid, \p runThread, \p hook, \p log.
    //! \param pid The process id.
    //! \param runThread A flag for running thread or just inplace loop.
    //! \param hook (experimental) A flag for hooking other process to avoid the blinking of two topmost processes.
    //! \param log A flag for logging process status.
    MakeTop(DWORD pid, bool runThread = true, bool hook = false, bool log = false) : 
        pid(pid), children(GetChildWindowHandles(pid)), setter(),
        runnable(false), runThread(runThread), hook(hook), log(log)
    {
        // make all child windows topmost
        SetChildWindowsTopMost();
        // run thread or inplace loop
        if (runThread) {
            RunThread();
        } else {
            runnable = true;
            Loop();
        }
    }

    //! Default destructor.
    ~MakeTop() {
        Stop();
    }

    MakeTop(MakeTop&& other) = delete;
    MakeTop(MakeTop const&) = delete;
    MakeTop& operator=(MakeTop&& other) = delete;
    MakeTop& operator=(MakeTop const&) = delete;

    //! Run thread to make process topmost constantly.
    void RunThread() {
        if (log) {
            logger() << "Start thread" << std::endl;
        }

        runnable = true;
        runThread = true;
        setter = std::thread([this] { Loop(); });
    }

    //! Make process topmost until runnable flag become false.
    void Loop() {
        if (log) {
            logger() << "Start Loop" << std::endl;
        }

        while (runnable) {
            // sleep term
            std::this_thread::sleep_for(term);

            // update child windows
            UpdateChildWindows();
            HWND hWnd = GetTopWindow(NULL);
            // default windows
            static std::set<std::string> blacklist = {
                "MSCTFIME UI", "Default IME", ""
            };

            while (hWnd != NULL) {
                // if given window is child window
                if (children.find(hWnd) != children.end()) {
                    break;
                }

                constexpr size_t bufsize = 1024;
                char text[bufsize] = { 0, };
                int read = GetWindowTextA(hWnd, text, bufsize);

                // if given window is not in blacklist
                if (blacklist.find(text) == blacklist.end()) {
                    if (log) {
                        logger() << "other topmost app found (name: " << text << ')' << std::endl;
                    }

                    // make topmost again
                    SetChildWindowsTopMost();
                    // experimental: hook other process's topmost api
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

    //! Stop topmost loop.
    void Stop() {
        // if loop is executed
        if (runnable) {
            runnable = false;
            // if thread is executed
            if (runThread) {
                setter.join();
                runThread = false;
            }
            // make child window notopmost
            for (HWND hWnd : children) {
                SetTopMost(hWnd, HWND_NOTOPMOST);
            }
        }
    }

    //! Set all child windows top most.
    void SetChildWindowsTopMost() {
        for (HWND hWnd : children) {
            SetTopMost(hWnd);
        }
    }

    //! Update child windows list.
    void UpdateChildWindows() {
        children = GetChildWindowHandles(pid);
    }

    std::ostream& logger() {
        return (std::cout << "[*] TopMost : ");
    }

    //! Call win32api to make window topmost or notopmost.
    //! \param hWnd The window handle.
    //! \param pos The flag for topmost or notopmost.
    static void SetTopMost(HWND hWnd, HWND pos = HWND_TOPMOST) {
        SetWindowPos(hWnd, pos, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
    }

    //! Get all child windows by process id.
    //! \param pid The process id.
    //! \return The set of child windows handle.
    static std::set<HWND> GetChildWindowHandles(DWORD pid) {
        std::pair<DWORD, std::set<HWND>> pair;
        pair.first = pid;

        // enumerate all windows
        BOOL bResult = EnumWindows([](HWND hWnd, LPARAM lpParam) {
            DWORD dwPid;
            auto param = reinterpret_cast<std::pair<DWORD, std::set<HWND>>*>(lpParam);
            // if given window is belong to given process
            if (GetWindowThreadProcessId(hWnd, &dwPid) && dwPid == param->first) {
                param->second.insert(hWnd);
            }
            return TRUE;
        }, reinterpret_cast<LPARAM>(&pair));

        return pair.second;
    }

    //! (experimental) Hook topmost api of other process.
    //! \param hWnd The target window handle.
    //! \param log The flag for logging.
    //! \return True for success, false for fail.
    static bool HookSetWindowPos(HWND hWnd, bool log = false) {
        // find process id by window handle
        DWORD dwPid;
        if (!GetWindowThreadProcessId(hWnd, &dwPid)) {
            if (log) {
                std::cout << "[*] Hook: GetWindowThreadProcessId fail" << std::endl;
            }
            return false;
        }
        return HookSetWindowPos(dwPid, log);
    }

    //! (experimental) Hook topmost api of other process.
    //! \param dwPid The target process id.
    //! \param log The flag for logging.
    //! \return True for success, false for fail.
    static bool HookSetWindowPos(DWORD dwPid, bool log = false) {
        // open target process
        HANDLE hProcess = OpenProcess(PROCESS_VM_OPERATION, FALSE, dwPid);
        if (hProcess == INVALID_HANDLE_VALUE) {
            if (log) {
                std::cout << "[*] Hook: OpenProcess fail" << std::endl;
            }
            return false;
        }

        // find address of SetWindowPos
        HMODULE hUser32 = GetModuleHandleW(L"User32.dll");
        FARPROC lpSetWindowPos = GetProcAddress(hUser32, "SetWindowPos");
        if (hUser32 == NULL || lpSetWindowPos == NULL) {
            if (log) {
                std::cout << "[*] Hook: GetProcAddress fail" << std::endl;
            }
            CloseHandle(hProcess);
            return false;
        }

        // mov eax, 1; ret
        static BYTE opcode[] = { 0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3, 0xCC, 0xCC };

        // grant write access privilege
        DWORD flOldProtect;
        if (!VirtualProtectEx(hProcess, lpSetWindowPos, sizeof(opcode), 
                              PAGE_EXECUTE_READWRITE, &flOldProtect))
        {
            if (log) {
                std::cout << "[*] Hook: VirtualProtectEx fail " << GetLastError() << std::endl;
            }
            CloseHandle(hProcess);
            return false;
        }

        // write process memory
        SIZE_T written;
        if (!WriteProcessMemory(hProcess, lpSetWindowPos, opcode, sizeof(opcode), &written)) {
            if (log) {
                std::cout << "[*] Hook: WriteProcessMemory fail " << GetLastError() << std::endl;
            }
            CloseHandle(hProcess);
            return false;
        }

        // recover privilege
        VirtualProtectEx(hProcess, lpSetWindowPos, sizeof(opcode), flOldProtect, &flOldProtect);
        CloseHandle(hProcess);

        return true;
    }
};
}

#endif