#include <iostream>

#include "TopMost.hpp"

int main() {
    std::cout <<
        "input format\n"
        "topmost current app : \"current\"\n"
        "pid base topmost : \"pid 1223\"\n"
        "window title base : \"title ConsoleApplication1 - Microsoft Visual Studio\"\n"
        "input: ";

    std::string opt;
    std::cin >> opt;

    std::unique_ptr<TopMost::MakeTop> topper;

    if (opt == "current") {
        topper = TopMost::MakeTop::CurrentProc(true, false, true);
    }
    else if (opt == "pid") {
        DWORD dwPid;
        std::cin >> dwPid;
        topper = std::make_unique<TopMost::MakeTop>(dwPid, true, false, true);
    }
    else if (opt == "title") {
        std::string name;
        std::getline(std::cin, name);

        topper = TopMost::MakeTop::ByName(name, true, false, true);
        if (topper == nullptr) {
            std::cout << "[*] Couldn't find window\n";
            return 1;
        }
    }
    else {
        std::cout << "[*] Invalid input\n";
        return 1;
    }

    system("pause");
    return 0;
}