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

    TopMost::MakeTop topper;

    if (opt == "current") {
        topper = TopMost::MakeTop::CurrentProc(false, false, true);
    }
    else if (opt == "pid") {
        DWORD dwPid;
        std::cin >> dwPid;
        topper = TopMost::MakeTop(dwPid, false, false, true);
    }
    else if (opt == "title") {
        std::string name;
        std::getline(std::cin, name);

        auto optTopper = TopMost::MakeTop::ByName(name, false, false, true);
        if (!optTopper.has_value()) {
            std::cout << "[*] Couldn't find window\n";
            return 1;
        }

        topper = std::move(optTopper.value());
    }
    else {
        std::cout << "[*] Invalid input\n";
        return 1;
    }

    std::cout << "Enter any value to stop topmost app" << std::endl;
    std::cin >> opt;

    return 0;
}