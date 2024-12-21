#include "whitelist.h"

namespace Whitelist {
    std::set<std::string> whitelist;  // Định nghĩa thực sự
    std::mutex whitelistMutex;        // Định nghĩa thực sự

    void add(const std::string& host) {
        std::lock_guard<std::mutex> lock(whitelistMutex); // Bảo vệ danh sách bằng mutex
        std::string clear_host = host;
        while (!clear_host.empty() && clear_host.back() == '/') clear_host.pop_back();
        
        if (clear_host.find("https://") != std::string::npos) {
            clear_host = clear_host.substr(8, clear_host.size() - 8);
        }
        if (clear_host.find("http://") != std::string::npos) {
            clear_host = clear_host.substr(7, clear_host.size() - 7);
        }

        whitelist.insert(clear_host);

        std::ofstream whitelistFile(WHITELIST_URL, std::ios::app);
        if (whitelistFile.is_open()) {
            whitelistFile << clear_host << '\n';
            whitelistFile.close();
            UI_WINDOW::UpdateLog("Adding " + clear_host + " to whitelist file.", std::string());
        } else {
            UI_WINDOW::UpdateLog("[Error] Could not write to whitelist file.", std::string());
        }
    }

    bool isAble(const std::string& host) {
        std::lock_guard<std::mutex> lock(whitelistMutex); // Bảo vệ danh sách bằng mutex
        // return whitelist.find(host) != whitelist.end();
        for (const auto& entry : whitelist) {
            if (entry == host) {
                return true; // Host nằm trong whitelist
            }

            // Kiểm tra nếu entry bắt đầu bằng '*'
            if (entry[0] == '*' && host.size() >= entry.size() - 1) {
                // So khớp phần sau của entry với host
                if (host.compare(host.size() - (entry.size() - 1), entry.size() - 1, entry.substr(1)) == 0) {
                    return true; // Host khớp với wildcard
                }
            }
        }

        return false;
    }

    void remove(const std::string& host) {
        std::lock_guard<std::mutex> lock(whitelistMutex); // Bảo vệ danh sách bằng mutex
        whitelist.erase(host);

        std::ofstream whitelistFile(WHITELIST_URL, std::ios::out);
        if (whitelistFile.is_open()) {
            for (std::string clear_host : whitelist) {
                whitelistFile << clear_host << '\n';
            }
            whitelistFile.close();
            UI_WINDOW::UpdateLog("Remove " + host + " from whitelist file.", std::string());
        } else {
            UI_WINDOW::UpdateLog("[Error] Could not write to whitelist file.", std::string());
        }
    }

    void load(const std::string& filename) {
        std::ifstream infile(filename);
        std::string line;
        whitelist.clear();
        while (std::getline(infile, line)) {
            while (not line.empty() and not isalpha(line.back())) line.pop_back();
            whitelist.insert(line);
        }
    }

    void updateListBox(HWND hWhitelistBox) {
        std::lock_guard<std::mutex> lock(whitelistMutex); // Bảo vệ danh sách bằng mutex
        std::string content;
        for (const auto& ip : whitelist) {
            content += ip + "\r\n";  // Thêm dòng mới giữa các mục
        }

        SetWindowTextA(hWhitelistBox, content.c_str());
    }
}
