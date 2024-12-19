#ifndef UI_H
#define UI_H

#include <winsock2.h>
#include <windows.h>
#include <thread>
#include <commctrl.h>
#include <string>
#include <iostream>
#include <atomic>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <commctrl.h>
#include <vector>
#include <gdiplus.h>

#include "font.h"
#include "blacklist.h"
#include "whitelist.h"
#include "network_init.h"
#include "network_handle.h"

namespace UI_WINDOW {
    extern std::atomic<bool> isProxyRunning; // Biến điều khiển trạng thái proxy
    extern int listType; // 0 - blacklist | 1 - whitelist

    // Khai báo các hàm liên quan đến giao diện
    void Init(HWND hwnd, HINSTANCE hInstance);
    void SetFontForControls(HWND hwnd);
    LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
    void UpdateRunningHosts(std::map<std::thread::id, std::pair<std::string, std::string>> threadMap);
    void UpdateLog(const std::string& str);
    void LogData(const std::string& direction, const std::string& data);
}

#endif
