#include "ui.h"

#define ID_LISTBOX_HOSTRUNNING 1001
namespace UI_WINDOW {
    // Global variables for UI elements
    static HWND hSaveListBtn;
    static HWND hStartProxyBtn;
    static HWND hListBox;
    static HWND hInstructions;
    static HWND hMember;
    static HWND hRunningHostsBox;       
    static HWND hListLabel;        
    static HWND hRunningHostsLabel;     
    static HWND hLogBox;  
    static HWND hLogBoxLabel;
    static HWND hStatusBar;
    static HWND hRequestBox;
    static HWND hRequestBoxLabel;
    static HWND hListType;
    static HWND hProxyServerType;

    // Global variable for controlling the proxy server
    std::atomic<bool> isProxyRunning(false);

    int listType = 0;
    int proxyServerType = 0;
    int requestBoxType = 0;

    // Internal function to start the proxy server
    static void startProxyServer() {
        SOCKET listenSocket = NetworkInit::startInitSocket();
        
        while (isProxyRunning) {
            fd_set readfds;
            FD_ZERO(&readfds);
            FD_SET(listenSocket, &readfds);

            struct timeval timeout = {1, 0}; // Timeout 1 giây
            int activity = select(0, &readfds, NULL, NULL, &timeout);

            if (activity > 0 && FD_ISSET(listenSocket, &readfds)) {
                // SOCKET clientSocket = accept(listenSocket, NULL, NULL);
                sockaddr_in clientAddr;
                int clientAddrSize = sizeof(clientAddr);
                SOCKET clientSocket = accept(listenSocket, (struct sockaddr*)&clientAddr, &clientAddrSize);
                if (clientSocket != INVALID_SOCKET) {
                    char clientIP[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &clientAddr.sin_addr, clientIP, INET_ADDRSTRLEN);
                    // UI_WINDOW::UpdateLog("Connection accepted from " + std::string(clientIP) + ":" + std::to_string(ntohs(clientAddr.sin_port)), std::string());

                    std::thread clientThread((proxyServerType == 0 ? TransparentNetworkHandle::handleClient : MITMNetworkHandle::handleClient), clientSocket);
                    clientThread.detach();
                }
            }
        }

        closesocket(listenSocket);
        WSACleanup();
    }

    // Set font for all UI elements
    void SetFontForControls(HWND hwnd) {
        Font::ApplyFontToControl(hSaveListBtn);
        Font::ApplyFontToControl(hStartProxyBtn);
        Font::ApplyFontToControl(hListBox);
        Font::ApplyFontToControl(hInstructions);
        Font::ApplyFontToControl(hMember);
        Font::ApplyFontToControl(hRunningHostsBox);
        Font::ApplyFontToControl(hListLabel);
        Font::ApplyFontToControl(hRunningHostsLabel);
        Font::ApplyFontToControl(hLogBox);
        Font::ApplyFontToControl(hLogBoxLabel);
        Font::ApplyFontToControl(hStatusBar);
        Font::ApplyFontToControl(hRequestBox);
        Font::ApplyFontToControl(hRequestBoxLabel);
        Font::ApplyFontToControl(hListType);     
        Font::ApplyFontToControl(hProxyServerType);     
    }

    // Initialize UI elements
    void Init(HWND hwnd, HINSTANCE hInstance) {
        hListLabel         = CreateWindowA("BUTTON", " Blacklist"          , WS_CHILD | WS_VISIBLE, 20, 20, 250, 25, hwnd, NULL, hInstance, NULL);
        hRunningHostsLabel = CreateWindowA("BUTTON", " Hosts Running"      , WS_CHILD | WS_VISIBLE, 450, 20, 300, 25, hwnd, NULL, hInstance, NULL);
        hLogBoxLabel       = CreateWindowA("BUTTON", " Logs"               , WS_CHILD | WS_VISIBLE, 450, 20, 300, 25, hwnd, NULL, hInstance, NULL);
        hRequestBoxLabel   = CreateWindowA("BUTTON", " Request Information", WS_CHILD | WS_VISIBLE, 450, 20, 300, 25, hwnd, (HMENU)5, hInstance, NULL);
        hStatusBar         = CreateWindowA("BUTTON", " Status: Ready"      , WS_CHILD | WS_VISIBLE | BS_LEFT, 20, 590, 730, 25, hwnd, NULL, hInstance, NULL);
        
        hSaveListBtn     = CreateWindowA("BUTTON", "Save Blacklist"   , WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_BORDER, 280, 60, 150, 30, hwnd, (HMENU)1, hInstance, NULL);
        hStartProxyBtn   = CreateWindowA("BUTTON", "Start Proxy"      , WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_BORDER, 620, 60, 150, 30, hwnd, (HMENU)2, hInstance, NULL);
        hListType        = CreateWindowA("BUTTON", "Type: Blacklist"  , WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_BORDER, 620, 60, 150, 30, hwnd, (HMENU)3, hInstance, NULL);
        hProxyServerType = CreateWindowA("BUTTON", " Transparent Proxy Server", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_BORDER, 620, 60, 150, 30, hwnd, (HMENU)4, hInstance, NULL);
        
        hLogBox     = CreateWindowA("EDIT", "", WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY | WS_BORDER, 20, 320, 730, 150, hwnd, NULL, hInstance, NULL);
        hListBox    = CreateWindowA("EDIT", "", WS_CHILD | WS_VISIBLE | ES_MULTILINE | WS_BORDER, 20, 100, 400, 200, hwnd, NULL, hInstance, NULL);
        hRequestBox = CreateWindowA("EDIT", "", WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_WANTRETURN | ES_READONLY | WS_BORDER, 20, 320, 730, 150, hwnd, NULL, hInstance, NULL);
        
        hRunningHostsBox    = CreateWindowExA(WS_EX_CLIENTEDGE, WC_LISTVIEW, "",
            WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_EDITLABELS | WS_BORDER,
            450, 100, 300, 200, hwnd, (HMENU)ID_LISTBOX_HOSTRUNNING, hInstance, NULL);
        
        SendMessage(hRunningHostsBox, LVM_SETBKCOLOR, 0, (LPARAM)RGB(255, 255, 224));
        SendMessage(hRunningHostsBox, LVM_SETTEXTBKCOLOR, 0, (LPARAM)RGB(255, 255, 224));

        // Define columns for ListView
        LVCOLUMN lvCol = {};
        lvCol.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;

        // Add "Host" column
        lvCol.cx = 150;
        lvCol.pszText = " Client IP Address - Host";
        ListView_InsertColumn(hRunningHostsBox, 0, &lvCol);

        // Add "Method" column
        lvCol.cx = 70;
        lvCol.pszText = " Method";
        ListView_InsertColumn(hRunningHostsBox, 1, &lvCol);

        // Add "URI" column
        lvCol.cx = 150;
        lvCol.pszText = " URI";
        ListView_InsertColumn(hRunningHostsBox, 2, &lvCol);

        // Add "HTTP Version" column
        lvCol.cx = 70;
        lvCol.pszText = " Version";
        ListView_InsertColumn(hRunningHostsBox, 3, &lvCol);

        // Add "Hostname" column
        lvCol.cx = 330;
        lvCol.pszText = " Hostname";
        ListView_InsertColumn(hRunningHostsBox, 4, &lvCol);

        // Initialize instructions
        std::string instructionsText = "\n"
                                    "    Instructions: Proxy Server\n"
                                    "    1. Hosts Running: Displays information about active hosts, including: host name, http method, http version\n"
                                    "    2. Request Information: Provides detailed information about a specific running host.\n"
                                    "    3. Blacklist: Lists hosts that are denied access by the proxy server.\n"
                                    "    4. Logs: All activity logs are saved daily in the 'logs' folder for review.\n";
        hInstructions = CreateWindowA("STATIC", instructionsText.c_str(), WS_CHILD | WS_VISIBLE | SS_LEFT, 20, 480, 730, 100, hwnd, NULL, hInstance, NULL);
        
        std::string memberText = "\n"
                                 "    Member:                         \n"
                                 "    1. Phan Ngung - 23120304.       \n"
                                 "    2. Vo Quoc Gia - 23120014.      \n"
                                 "    3. Tran Minh Hieu Hoc - 23120006\n";
        hMember = CreateWindowA("STATIC", memberText.c_str(), WS_CHILD | WS_VISIBLE | SS_LEFT, 20, 480, 730, 100, hwnd, NULL, hInstance, NULL);

        SetFontForControls(hwnd);
        Blacklist::updateListBox(hListBox);
    }

    ULONG_PTR gdiplusToken;
    Gdiplus::Image* g_image = nullptr;

    // Handle UI events
    LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
        Gdiplus::GdiplusStartupInput gdiplusStartupInput;
        Gdiplus::GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, NULL);
        
        static std::thread proxyThread;
        switch (uMsg) {
            case WM_CREATE: {
                // Tải ảnh PNG khi cửa sổ được tạo
                g_image = new Gdiplus::Image(LOGO_URL);
                if (g_image->GetLastStatus() != Gdiplus::Ok) {
                    UpdateLog("Can not load image PNG!", std::string());
                    delete g_image;
                    g_image = nullptr;
                }
                break;
            }
            case WM_COMMAND: {
                switch (LOWORD(wParam)) {
                    case 1: { // Save to blacklist - whitelist
                        // Lấy độ dài nội dung
                        int length = GetWindowTextLengthA(hListBox);
 
                        char* buffer = new char[length + 1];  // Cấp phát bộ nhớ
                        GetWindowTextA(hListBox, buffer, length + 1);  // Lấy nội dung

                        // Lưu vào file hoặc xử lý tùy ý
                        std::ofstream outFile(listType == 0 ? BLACKLIST_URL : WHITELIST_URL);
                        if (outFile) {
                            outFile << buffer;  // Ghi nội dung vào file
                            outFile.close();
                        }

                        if (listType == 0) {
                            Blacklist::load(BLACKLIST_URL);
                        } else {
                            Whitelist::load(WHITELIST_URL);
                        }

                        std::string message = (std::string)(listType == 0 ? "Blacklist" : "Whitelist") + (std::string)" saved successfully!"; 
                        UpdateLog(message, std::string());
                        message = (std::string)"Status: " + message;
                        SetWindowTextA(hStatusBar, message.c_str());
                        delete[] buffer;  // Giải phóng bộ nhớ

                        break;
                    }
                    case 2: { // Toggle Proxy server (Start/Stop)
                        if (isProxyRunning) {
                            // Stop the proxy server
                            isProxyRunning = false;
                            if (proxyThread.joinable()) {
                                proxyThread.join();
                            }
                            SetWindowTextA(hStartProxyBtn, " Start Proxy");  // Change the button text
                            SetWindowTextA(hStatusBar, " Status: Proxy server stopped");
                            UpdateLog("Proxy server stopped.", std::string());
                        } else {
                            // Start the proxy server
                            isProxyRunning = true;
                            proxyThread = std::thread(startProxyServer);
                            SetWindowTextA(hStartProxyBtn, " Stop Proxy");  // Change the button text
                            SetWindowTextA(hStatusBar, " Status: Proxy server running");
                        }
                        break;
                    }
                    case 3: { // Change Blacklist <-> Whitelist
                        if (listType == 0) {
                            listType = 1;
                            SetWindowTextA(hListType, "Type: Whitelist");
                            SetWindowTextA(hListLabel, " Whitelist");
                            SetWindowTextA(hSaveListBtn, "Save Whitelist");
                            SetWindowTextA(hStatusBar, " Status: Change to Whitelist");
                            Whitelist::updateListBox(hListBox);
                        } else {
                            listType = 0;
                            SetWindowTextA(hListType, "Type: Blacklist");
                            SetWindowTextA(hListLabel, " Blacklist");
                            SetWindowTextA(hSaveListBtn, "Save Blacklist");
                            SetWindowTextA(hStatusBar, " Status: Change to Blacklist");
                            Blacklist::updateListBox(hListBox);
                        }
                        break;
                    }
                    case 4: {
                        if (proxyServerType == 0) {
                            proxyServerType = 1;
                            SetWindowTextA(hProxyServerType, " Man In The Middle Proxy Server");
                        } else {
                            proxyServerType = 0;
                            SetWindowTextA(hProxyServerType, " Transparent Proxy Server");
                        }
                        break;
                    }
                    case 5: {
                        if (requestBoxType == 0) {
                            requestBoxType = 1;
                            SetWindowTextA(hRequestBoxLabel, " Request Data - MITM");
                        } else {
                            requestBoxType = 0;
                            SetWindowTextA(hRequestBoxLabel, " Request Information");
                        }
                    }
                }

                if (requestBoxType == 0 && LOWORD(wParam) == ID_LISTBOX_HOSTRUNNING && HIWORD(wParam) == LVN_ITEMCHANGED) {
                    // Lấy chỉ số của dòng được chọn
                    int index = ListView_GetNextItem(hRunningHostsBox, -1, LVNI_SELECTED);
                    if (index != -1) { // Kiểm tra nếu có dòng nào được chọn
                        char buffer[256];
                        
                        // Lấy giá trị của cột đầu tiên ("Host") từ dòng được chọn
                        ListView_GetItemText(hRunningHostsBox, index, 0, buffer, sizeof(buffer));

                        // Giả lập gửi request để lấy thông tin liên quan từ hostRequestMap
                        std::string requestMessage = (proxyServerType == 0 ? TransparentNetworkHandle::hostRequestMap[buffer] : MITMNetworkHandle::hostRequestMap[buffer]);

                        // Hiển thị nội dung request trong `hRequestBox`
                        SetWindowText(hRequestBox, requestMessage.c_str());
                    }
                }

                break;
            }
            case WM_NOTIFY: {
                LPNMHDR nmhdr = (LPNMHDR)lParam;
                if (requestBoxType == 0 && nmhdr->idFrom == ID_LISTBOX_HOSTRUNNING && nmhdr->code == LVN_ITEMCHANGED) {
                    // Gọi logic xử lý khi một dòng trong ListView được chọn
                    NMLISTVIEW* pnmv = (NMLISTVIEW*)lParam;
                    if (pnmv->uNewState & LVIS_SELECTED) {
                        int index = pnmv->iItem;
                        char buffer[256];
                        ListView_GetItemText(hRunningHostsBox, index, 0, buffer, sizeof(buffer));
                        std::string requestMessage = (proxyServerType == 0 ? TransparentNetworkHandle::hostRequestMap[buffer] : MITMNetworkHandle::hostRequestMap[buffer]);
                        SetWindowText(hRequestBox, requestMessage.c_str());
                    }
                }
                break;
            }
            case WM_CTLCOLORSTATIC: {
                // Kiểm tra nếu control là một trong các hộp cần thay đổi màu nền
                HWND hControl = (HWND)lParam;
                if (hControl == hListBox || hControl == hRunningHostsBox || hControl == hLogBox || hControl == hRequestBox) {
                    HDC hdc = (HDC)wParam;
                    // Tạo brush với màu nền xám
                    HBRUSH hBrush = CreateSolidBrush(RGB(255, 255, 224)); // Màu xám
                    SetBkColor(hdc, RGB(255, 255, 224)); // Màu nền xám
                    SetTextColor(hdc, RGB(0, 0, 0)); // Màu chữ trắng

                    // Trả về brush để tô nền
                    return (LRESULT)hBrush;
                }
                break;
            }
            case WM_CTLCOLORLISTBOX: {
                // Nếu là ListBox, áp dụng màu nền xám
                HWND hControl = (HWND)lParam;
                if (hControl == hListBox || hControl == hRunningHostsBox || hControl == hLogBox || hControl == hRequestBox) {
                    HDC hdc = (HDC)wParam;
                    // Tạo brush với màu nền xám
                    HBRUSH hBrush = CreateSolidBrush(RGB(255, 255, 224)); // Màu xám
                    SetBkColor(hdc, RGB(255, 255, 224)); // Màu nền xám
                    SetTextColor(hdc, RGB(0, 0, 0)); // Màu chữ trắng
                    // Trả về brush để tô nền
                    return (LRESULT)hBrush;
                }
                break;
            }
            case WM_CTLCOLOREDIT: {
                // Nếu là Edit control, áp dụng màu nền xám
                HWND hControl = (HWND)lParam;
                if (hControl == hListBox || hControl == hRunningHostsBox || hControl == hLogBox || hControl == hRequestBox) {
                    HDC hdc = (HDC)wParam;
                    // Tạo brush với màu nền xám
                    HBRUSH hBrush = CreateSolidBrush(RGB(255, 255, 224)); // Màu xám
                    SetBkColor(hdc, RGB(255, 255, 224)); // Màu nền xám
                    SetTextColor(hdc, RGB(0, 0, 0)); // Màu chữ trắng

                    // Trả về brush để tô nền
                    return (LRESULT)hBrush;
                }
                break;
            }
            case WM_SIZE: {
                int width = LOWORD(lParam);  // Get window width
                int height = HIWORD(lParam); // Get window height

                int padding = 10;
                int buttonWidth = 150;
                int buttonHeight = 25;
                int listBoxHeight = (height - 280) / 2;  
                int instructionsHeight = 120; 
                int column2X = width / 2;
                int listBoxWidth = column2X - 2 * padding;

                int x = padding, y = 20;
                MoveWindow(hRunningHostsLabel, x, y               , listBoxWidth, buttonHeight , TRUE);
                MoveWindow(hRunningHostsBox  , x, y + buttonHeight, listBoxWidth, listBoxHeight, TRUE);

                MoveWindow(hRequestBoxLabel, column2X + x, y               , width - column2X - 2 * padding, buttonHeight , TRUE);
                MoveWindow(hRequestBox     , column2X + x, y + buttonHeight, width - column2X - 2 * padding, listBoxHeight, TRUE);

                x = padding, y = 20 + buttonHeight + listBoxHeight + padding;
                MoveWindow(hListLabel, x + listBoxWidth / 2, y               , listBoxWidth / 2, buttonHeight , TRUE);
                MoveWindow(hListBox  , x + listBoxWidth / 2, y + buttonHeight, listBoxWidth / 2, listBoxHeight, TRUE);

                MoveWindow(hLogBoxLabel, column2X + x, y               , listBoxWidth, buttonHeight , TRUE);
                MoveWindow(hLogBox     , column2X + x, y + buttonHeight, listBoxWidth, listBoxHeight, TRUE);

                x = padding, y = 20 + buttonHeight + listBoxHeight + padding + buttonHeight + listBoxHeight + padding + padding;

                MoveWindow(hProxyServerType, x, y, listBoxWidth / 2 - padding, buttonHeight, TRUE); 

                MoveWindow(hListType   , x + listBoxWidth / 2                   , y, listBoxWidth / 4 - padding / 2, buttonHeight, TRUE); 
                MoveWindow(hSaveListBtn, x + listBoxWidth / 2 + listBoxWidth / 4 + padding / 2, y, listBoxWidth / 4 - padding / 2, buttonHeight, TRUE); 
                
                MoveWindow(hStartProxyBtn, column2X + x                        , y, buttonWidth                         , buttonHeight, TRUE);
                MoveWindow(hStatusBar    , column2X + x + buttonWidth + padding, y, listBoxWidth - buttonWidth - padding, buttonHeight, TRUE);
                
                MoveWindow(hInstructions, padding, height - instructionsHeight - padding, (width - 2 * padding) / 2, instructionsHeight, TRUE);
                MoveWindow(hMember      , padding + (width - 2 * padding) / 2, height - instructionsHeight - padding, (width - 2 * padding) / 2, instructionsHeight, TRUE);
                
                InvalidateRect(hwnd, NULL, TRUE);
                break;
            }
            case WM_PAINT: {
                PAINTSTRUCT ps;
                HDC hdc = BeginPaint(hwnd, &ps);

                // Tô nền màu trắng
                RECT rect;
                GetClientRect(hwnd, &rect);
                HBRUSH brush = CreateSolidBrush(RGB(255, 255, 255));
                FillRect(hdc, &rect, brush);
                DeleteObject(brush);

                int width = rect.right - rect.left;  // Get window width
                int height = rect.bottom - rect.top; // Get window height

                int padding = 10;
                int buttonHeight = 25;
                int listBoxHeight = (height - 280) / 2;  
                int column2X = width / 2;
                int listBoxWidth = column2X - 2 * padding;

                int x = padding, y = 20 + buttonHeight + listBoxHeight + padding;
                if (g_image) {
                    Gdiplus::Graphics graphics(hdc);
                    int g_image_size = std::min(listBoxWidth / 2, listBoxHeight);
                    graphics.DrawImage(g_image, (x + listBoxWidth / 2 - g_image_size) / 2, y + buttonHeight, g_image->GetWidth() / g_image->GetHeight() * g_image_size, g_image_size);
                }

                EndPaint(hwnd, &ps);
                break;
            }
            case WM_DESTROY: {
                isProxyRunning = false;
                UpdateLog("Exit proxy server ...", std::string());
                if (g_image) {
                    delete g_image;
                    g_image = nullptr;
                }
                Gdiplus::GdiplusShutdown(gdiplusToken);
                PostQuitMessage(0);
                break;
            }
            default:
                return DefWindowProc(hwnd, uMsg, wParam, lParam);
        }
        return 0;
    }

    void UpdateRunningHosts(std::map<std::thread::id, std::tuple<std::string, std::string, std::string>> threadMap) {
        // Lưu danh sách các Host hiện tại trong ListView
        std::set<std::string> existingHosts;
        int itemCount = ListView_GetItemCount(hRunningHostsBox);

        for (int i = 0; i < itemCount; ++i) {
            char buffer[128];
            ListView_GetItemText(hRunningHostsBox, i, 0, buffer, sizeof(buffer));
            existingHosts.insert(std::string(buffer)); // Lưu Host (cột đầu tiên)
        }

        // Duyệt qua threadMap để thêm hoặc cập nhật các mục
        for (const auto& [id, data] : threadMap) {
            const std::string& clientIP = std::get<0>(data);
            const std::string& host = std::get<1>(data);
            const std::string& request = std::get<2>(data);

            std::string hostKey = clientIP + (std::string)" - " + host;

            if (existingHosts.find(hostKey) == existingHosts.end()) {
                // Nếu Host chưa tồn tại trong bảng, thêm mới
                std::string method, uri, httpVersion, hostName;

                // Phân tích chuỗi request
                std::istringstream requestStream(request);
                requestStream >> method >> uri >> httpVersion;

                // Tìm "Host: " trong request để lấy hostName
                std::string line;
                while (std::getline(requestStream, line)) {
                    if (line.find("Host: ") == 0) {
                        hostName = line.substr(6);
                        break;
                    }
                }

                // Thêm vào ListView
                LVITEM lvItem = {};
                lvItem.mask = LVIF_TEXT;
                lvItem.iItem = ListView_GetItemCount(hRunningHostsBox); // Row index
                lvItem.pszText = (LPSTR)hostKey.c_str(); // Host (cột đầu tiên)
                ListView_InsertItem(hRunningHostsBox, &lvItem);

                ListView_SetItemText(hRunningHostsBox, lvItem.iItem, 1, (LPSTR)method.c_str());
                ListView_SetItemText(hRunningHostsBox, lvItem.iItem, 2, (LPSTR)uri.c_str());
                ListView_SetItemText(hRunningHostsBox, lvItem.iItem, 3, (LPSTR)httpVersion.c_str());
                ListView_SetItemText(hRunningHostsBox, lvItem.iItem, 4, (LPSTR)hostName.c_str());
            }
        }

        // Xóa các mục không còn trong threadMap
        for (int i = 0; i < itemCount; ++i) {
            char buffer[128];
            ListView_GetItemText(hRunningHostsBox, i, 0, buffer, sizeof(buffer));
            std::string hostKey(buffer);

            bool found = false;
            for (const auto& [id, data] : threadMap) {
                const std::string& clientIP = std::get<0>(data);
                const std::string& host = std::get<1>(data);
                if (hostKey == (clientIP + (std::string)" - " + host)) {
                    found = true;
                    break;
                }
            }

            if (!found) {
                ListView_DeleteItem(hRunningHostsBox, i);
                --i; // Điều chỉnh chỉ số sau khi xóa
                --itemCount;
            }
        }

        // Tự động điều chỉnh kích thước các cột
        for (int i = 0; i < 5; ++i) {
            ListView_SetColumnWidth(hRunningHostsBox, i, LVSCW_AUTOSIZE);
            ListView_SetColumnWidth(hRunningHostsBox, i, LVSCW_AUTOSIZE_USEHEADER);
        }

        // Kiểm tra dòng nào đang được chọn
        int index = ListView_GetNextItem(hRunningHostsBox, -1, LVNI_SELECTED);
        
        // Nếu không có dòng nào được chọn, tự động chọn dòng đầu tiên
        if (requestBoxType == 0 && index == -1) { 
            index = 0; // Dòng đầu tiên trong danh sách
            // Kiểm tra xem dòng đầu tiên có dữ liệu hay không
            char testBuffer[256] = {0};
            ListView_GetItemText(hRunningHostsBox, index, 0, testBuffer, sizeof(testBuffer));
            if (strlen(testBuffer) == 0) {
                SetWindowText(hRequestBox, std::string().c_str());
                return; // Dòng đầu tiên rỗng, không làm gì cả
            }
            // Chọn dòng đầu tiên
            ListView_SetItemState(hRunningHostsBox, index, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
            ListView_EnsureVisible(hRunningHostsBox, index, FALSE); // Đảm bảo dòng được nhìn thấy
        }
        
        if (requestBoxType == 0) {
            // Tiếp tục xử lý dòng đã chọn
            char buffer[256];

            // Lấy giá trị của cột đầu tiên ("Host") từ dòng được chọn
            ListView_GetItemText(hRunningHostsBox, index, 0, buffer, sizeof(buffer));
            
            // Giả lập gửi request để lấy thông tin liên quan từ hostRequestMap
            std::string requestMessage = (proxyServerType == 0 ? TransparentNetworkHandle::hostRequestMap[buffer] : MITMNetworkHandle::hostRequestMap[buffer]);

            // Hiển thị nội dung request trong `hRequestBox`
            SetWindowText(hRequestBox, requestMessage.c_str());
        }
    }

    void UpdateLog(const std::string& str, const std::string& clientIP) {
        // Get current time
        auto now = std::chrono::system_clock::now();
        auto now_time_t = std::chrono::system_clock::to_time_t(now);
        std::tm tm = *std::localtime(&now_time_t);

        // Format time as HH:MM:SS
        std::ostringstream timeStream;
        timeStream << std::put_time(&tm, "%H:%M:%S");

        // Create the final log message with time prefix
        std::string logMessage = "[" + timeStream.str() + "] " + clientIP + ": " + str;

        // Add the log message to the listbox
        // SendMessage(hLogBox, LB_ADDSTRING, 0, (LPARAM)logMessage.c_str());

        // Get the current content of the EDIT control
        int length = GetWindowTextLengthA(hLogBox);
        std::vector<char> buffer(length + 1);
        GetWindowTextA(hLogBox, buffer.data(), length + 1);

        // Append the new log message
        std::string currentLog(buffer.begin(), buffer.end() - 1);
        currentLog += logMessage + "\r\n";
        // std::cout << currentLog << '\n';
        // Set the updated content back to the EDIT control
        SetWindowTextA(hLogBox, currentLog.c_str());

        // Automatically scroll to the bottom of the listbox
        // int count = SendMessage(hLogBox, LB_GETCOUNT, 0, 0);
        // SendMessage(hLogBox, LB_SETTOPINDEX, count - 1, 0);
        SendMessage(hLogBox, EM_SETSEL, currentLog.length(), currentLog.length());
        SendMessage(hLogBox, EM_SCROLLCARET, 0, 0);

        // Prepare log file name: log_dd_mm_yy.txt
        std::ostringstream fileNameStream;
        fileNameStream << "log_"
                    << std::put_time(&tm, "%d_%m_%y") 
                    << ".txt";
        std::string logFileName = fileNameStream.str();

        // Folder to store logs (adjust as needed)
        std::string logFolder = "logs/";

        // Full path to log file
        std::string logFilePath = logFolder + logFileName;

        // Write the log message to the file
        std::ofstream logFile(logFilePath, std::ios::app);
        if (logFile.is_open()) {
            logFile << logMessage << '\n';
            logFile.close();
        } else {
            // Optionally handle errors when opening the file
            // SendMessage(hLogBox, LB_ADDSTRING, 0, (LPARAM)"[Error] Could not write to log file.");
            std::string errorMessage = "[Error] Could not write to log file.\r\n";
            currentLog += errorMessage;
            SetWindowTextA(hLogBox, currentLog.c_str());
        }
    }

    void LogData(const std::string& direction, const std::string& data, const std::string& clientIP) {
        if (requestBoxType == 1) {
            // int length = GetWindowTextLengthA(hRequestBox);
            // std::vector<char> buffer(length + 1);
            // GetWindowTextA(hRequestBox, buffer.data(), length + 1);

            // // Append the new log message
            // std::string currentLog(buffer.begin(), buffer.end() - 1);
            // currentLog += data + "\r\n";
            // // std::cout << currentLog << '\n';
            // // Set the updated content back to the EDIT control
            SetWindowTextA(hRequestBox, (clientIP + ": " + data).c_str());
        }

        // Get current time
        auto now = std::chrono::system_clock::now();
        auto now_time_t = std::chrono::system_clock::to_time_t(now);
        std::tm tm;
        localtime_s(&tm, &now_time_t); // Sử dụng localtime_s cho thread safety

        // Format time as HH:MM:SS
        std::ostringstream timeStream;
        timeStream << std::put_time(&tm, "%H:%M:%S");

        // Create the final log message with time prefix and direction
        std::string logMessage = "[" + timeStream.str() + "] " + clientIP + " " + direction + ": " + data;

        // Prepare log file name: log_dd_mm_yy.txt
        std::ostringstream fileNameStream;
        fileNameStream << "logData_"
                       << std::put_time(&tm, "%d_%m_%y")
                       << ".txt";
        std::string logFileName = fileNameStream.str();

        // Folder to store logs (adjust as needed)
        std::string logFolder = "logs/";

        // Ensure the log folder exists
        CreateDirectoryA(logFolder.c_str(), NULL); // Không quan tâm đến lỗi nếu thư mục đã tồn tại

        // Full path to log file
        std::string logFilePath = logFolder + logFileName;

        // Write the log message to the file
        std::ofstream logFile(logFilePath, std::ios::app);
        if (logFile.is_open()) {
            logFile << logMessage << '\n';
            logFile.close();
        } else {
            // Optionally handle errors when opening the file
            std::string errorMessage = "[Error] Could not write to log file.\r\n";
            SetWindowTextA(hLogBox, errorMessage.c_str());
        }
    }
}
