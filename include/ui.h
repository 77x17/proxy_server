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
#include <map>
#include <set>
#include <ws2tcpip.h>

#include "font.h"
#include "blacklist.h"
#include "whitelist.h"
#include "network_init.h"
#include "mitm_network_handle.h"
#include "transparent_network_handle.h"

namespace UI_WINDOW {
    extern std::atomic<bool> isProxyRunning; // Biến điều khiển trạng thái proxy
    extern int listType; // 0 - blacklist | 1 - whitelist

    // Khai báo các hàm liên quan đến giao diện
    void             Init(HWND hwnd, HINSTANCE hInstance);
    void             SetFontForControls(HWND hwnd);
    LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
    void             UpdateRunningHosts(std::map<std::thread::id, std::tuple<std::string, std::string, std::string>> threadMap);
    void             UpdateLog(const std::string& str, const std::string& clientIP);
    void             LogData(const std::string& direction, const std::string& data, const std::string& clientIP);
}

#endif
