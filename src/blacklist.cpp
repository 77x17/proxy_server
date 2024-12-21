#include "blacklist.h"

namespace Blacklist {
    std::set<std::string> blacklist;  // Định nghĩa thực sự
    std::mutex blacklistMutex;        // Định nghĩa thực sự

    void add(const std::string& host) {
        std::lock_guard<std::mutex> lock(blacklistMutex); // Bảo vệ danh sách bằng mutex
        std::string clear_host = host;
        while (!clear_host.empty() && clear_host.back() == '/') clear_host.pop_back();
        
        if (clear_host.find("https://") != std::string::npos) {
            clear_host = clear_host.substr(8, clear_host.size() - 8);
        }
        if (clear_host.find("http://") != std::string::npos) {
            clear_host = clear_host.substr(7, clear_host.size() - 7);
        }

        blacklist.insert(clear_host);

        std::ofstream blacklistFile(BLACKLIST_URL, std::ios::app);
        if (blacklistFile.is_open()) {
            blacklistFile << clear_host << '\n';
            blacklistFile.close();
            UI_WINDOW::UpdateLog("Adding " + clear_host + " to blacklist file.", std::string());
        } else {
            UI_WINDOW::UpdateLog("[Error] Could not write to blacklist file.", std::string());
        }
    }

    bool isBlocked(const std::string& host) {
        std::lock_guard<std::mutex> lock(blacklistMutex); // Bảo vệ danh sách bằng mutex
        return blacklist.find(host) != blacklist.end();
    }

    void remove(const std::string& host) {
        std::lock_guard<std::mutex> lock(blacklistMutex); // Bảo vệ danh sách bằng mutex
        blacklist.erase(host);

        std::ofstream blacklistFile(BLACKLIST_URL, std::ios::out);
        if (blacklistFile.is_open()) {
            for (std::string clear_host : blacklist) {
                blacklistFile << clear_host << '\n';
            }
            blacklistFile.close();
            UI_WINDOW::UpdateLog("Remove " + host + " from blacklist file.", std::string());
        } else {
            UI_WINDOW::UpdateLog("[Error] Could not write to blacklist file.", std::string());
        }
    }

    void load(const std::string& filename) {
        std::ifstream infile(filename);
        std::string line;
        blacklist.clear();
        while (std::getline(infile, line)) {
            while (not line.empty() and not isalpha(line.back())) line.pop_back();
            std::string clear_host = line;
            while (!clear_host.empty() && clear_host.back() == '/') clear_host.pop_back();
            
            if (clear_host.find("https://") != std::string::npos) {
                clear_host = clear_host.substr(8, clear_host.size() - 8);
            }
            if (clear_host.find("http://") != std::string::npos) {
                clear_host = clear_host.substr(7, clear_host.size() - 7);
            }

            blacklist.insert(clear_host);
        }
    }

    void updateListBox(HWND hBlackListBox) {
        std::lock_guard<std::mutex> lock(blacklistMutex); // Bảo vệ danh sách bằng mutex
        std::string content;
        for (const auto& ip : blacklist) {
            content += ip + "\r\n";  // Thêm dòng mới giữa các mục
        }

        SetWindowTextA(hBlackListBox, content.c_str());
    }
}
