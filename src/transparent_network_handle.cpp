#include "transparent_network_handle.h"

namespace TransparentNetworkHandle {
    std::atomic<int> activeThreads(0);                                        // Quản lý các luồng đang hoạt động
    std::map<std::thread::id, std::pair<std::string, std::string>> threadMap; // Danh sách luồng và URL
    std::mutex threadMapMutex;                                                // Mutex để đồng bộ
    std::map<std::thread::id, std::atomic<bool>> stopFlags;                   // Cờ dừng cho từng luồng

    std::map<std::string, std::string> hostRequestMap;

    std::string parseHttpRequest(const std::string& request) {
        size_t pos = request.find("Host: ");
        if (pos == std::string::npos) return std::string();

        size_t start = pos + 6;
        size_t end = request.find("\r\n", start);
        if (end == std::string::npos) return std::string();

        return request.substr(start, end - start);
    }

    void printActiveThreads() {
        std::lock_guard<std::mutex> lock(threadMapMutex);
        UI_WINDOW::UpdateRunningHosts(threadMap); // Gửi thông tin lên giao diện
    }

    // Function to check active threads and stop the ones with a Blacklisted HOST
    void checkAndStopBlacklistedThreads() {
        std::lock_guard<std::mutex> lock(threadMapMutex); 
        for (auto& [id, host] : threadMap) {
            if (UI_WINDOW::listType == 0) {
                if (Blacklist::isBlocked(host.first)) {
                    stopFlags[id] = true;  // Set flag to true to stop the thread
                }
            } else {
                if (not Whitelist::isAble(host.first)) {
                    stopFlags[id] = true;
                }
            }
        }
    }

    void handleConnectMethod(SOCKET clientSocket, const std::string& host, int port) {
        // Tạo socket để kết nối đến server đích
        SOCKET remoteSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (remoteSocket == INVALID_SOCKET) {
            UI_WINDOW::UpdateLog("Cannot create remote socket.");
            return;
        }

        // Định nghĩa địa chỉ của server đích
        sockaddr_in serverAddr;
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_port = htons(port); 

        struct hostent* remoteHost = gethostbyname(host.c_str());
        if (remoteHost == NULL) {
            UI_WINDOW::UpdateLog("Cannot resolve hostname.");
            closesocket(remoteSocket);
            return;
        }
        memcpy(&serverAddr.sin_addr.s_addr, remoteHost->h_addr, remoteHost->h_length);

        // Kết nối đến server đích
        if (connect(remoteSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
            UI_WINDOW::UpdateLog("Cannot connect to remote server.");
            closesocket(remoteSocket);
            return;
        }

        // Gửi phản hồi 200 Connection Established cho client
        const char* established = "HTTP/1.1 200 Connection Established\r\n\r\n";
        send(clientSocket, established, strlen(established), 0);

        // Tạo kết nối hai chiều giữa client và server
        fd_set readfds;                                      // Tập các socket đang đợi để đọc
        char buffer[BUFFER_SIZE];
        while (not stopFlags[std::this_thread::get_id()]) {  // Kiểm tra nếu thread cần dừng 
            if (UI_WINDOW::isProxyRunning == false) {
                UI_WINDOW::UpdateLog("Disconnecting: " + host + " || Reason: Stopped proxy.");
                break;
            }
            FD_ZERO(&readfds);                               // Xóa tập readfds
            FD_SET(clientSocket, &readfds);                  // Thêm clientSocket vào tập readfds
            FD_SET(remoteSocket, &readfds);                  // Thêm remoteSocket vào tập readfds

            struct timeval timeout;
            timeout.tv_sec = 10;                             // Chờ tối đa 10 giây
            timeout.tv_usec = 0;
            if (select(0, &readfds, NULL, NULL, &timeout) <= 0) { // select() trả socket chứa dữ liệu có thể đọc
                UI_WINDOW::UpdateLog("Disconnecting: " + host + " || Reason: Timeout occurred, closing connection.");
                break;
            }

            if (FD_ISSET(clientSocket, &readfds)) {
                int receivedBytes = recv(clientSocket, buffer, BUFFER_SIZE, 0);
                if (receivedBytes <= 0) break;
                send(remoteSocket, buffer, receivedBytes, 0);
            }
            if (FD_ISSET(remoteSocket, &readfds)) {
                int receivedBytes = recv(remoteSocket, buffer, BUFFER_SIZE, 0);
                if (receivedBytes <= 0) break;
                send(clientSocket, buffer, receivedBytes, 0);
            }
        }

        closesocket(remoteSocket);
    }

    void handleHttpRequest(SOCKET clientSocket, const std::string& host, int port, const std::string& request) {
        // Kết nối đến server thật
        SOCKET remoteSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (remoteSocket == INVALID_SOCKET) {
            UI_WINDOW::UpdateLog("Cannot create remote socket.");
            
            return;
        }

        sockaddr_in serverAddr;
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_port = htons(port);
        struct hostent* remoteHost = gethostbyname(host.c_str());
        if (remoteHost == NULL) {
            UI_WINDOW::UpdateLog("Cannot resolve hostname: " + host);
            closesocket(remoteSocket);
            
            return;
        }
        memcpy(&serverAddr.sin_addr.s_addr, remoteHost->h_addr, remoteHost->h_length);

        if (connect(remoteSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
            UI_WINDOW::UpdateLog("Cannot connect to remote server: " + host + ":" + std::to_string(port));
            closesocket(remoteSocket);
            
            return;
        }

        UI_WINDOW::UpdateLog("Connected to remote server for HTTP request: " + host + ":" + std::to_string(port));

        // Gửi yêu cầu đến server
        send(remoteSocket, request.c_str(), request.size(), 0);

        // Relay dữ liệu từ server tới client
        fd_set readfds;
        char buffer_data[BUFFER_SIZE];
        bool connectionOpen = true;
        while (connectionOpen) {
            FD_ZERO(&readfds);
            FD_SET(clientSocket, &readfds);
            FD_SET(remoteSocket, &readfds);

            struct timeval timeout;
            timeout.tv_sec = 30;
            timeout.tv_usec = 0;

            int maxfd = (clientSocket > remoteSocket) ? clientSocket : remoteSocket;
            int activity = select(maxfd + 1, &readfds, NULL, NULL, &timeout);
            if (activity < 0) {
                UI_WINDOW::UpdateLog("Select error in HTTP request handling.");
                break;
            }
            if (activity == 0) {
                UI_WINDOW::UpdateLog("Timeout occurred, closing HTTP connection.");
                break;
            }

            if (FD_ISSET(remoteSocket, &readfds)) {
                int receivedBytes = recv(remoteSocket, buffer_data, sizeof(buffer_data), 0);
                if (receivedBytes <= 0) {
                    connectionOpen = false;
                    break;
                }

                // Log dữ liệu từ server
                std::string data(buffer_data, receivedBytes);
                UI_WINDOW::LogData("Server -> Client:", data);

                // Gửi dữ liệu tới client
                send(clientSocket, buffer_data, receivedBytes, 0);
            }

            if (FD_ISSET(clientSocket, &readfds)) {
                int receivedBytes = recv(clientSocket, buffer_data, sizeof(buffer_data), 0);
                if (receivedBytes <= 0) {
                    connectionOpen = false;
                    break;
                }

                // Log dữ liệu từ client
                std::string data(buffer_data, receivedBytes);
                UI_WINDOW::LogData("Client -> Server:", data);

                // Gửi dữ liệu tới server
                send(remoteSocket, buffer_data, receivedBytes, 0);
            }
        }

        // Đóng kết nối
        closesocket(remoteSocket);
    }

    void handleClient(SOCKET clientSocket) {
        char buffer[BUFFER_SIZE];
        int receivedBytes = recv(clientSocket, buffer, BUFFER_SIZE, 0);
        if (receivedBytes <= 0) {   
            // UI_WINDOW::UpdateLog("No data received or connection closed by client.");
            return;
        }

        std::string request(buffer, receivedBytes);
        // Kiểm tra xem yêu cầu có phải là CONNECT hay không
        if (request.substr(0, 3) == "GET" || request.substr(0, 4) == "POST") {
            // Xử lý GET/POST trong luồng riêng
            std::string host = parseHttpRequest(request);
            if (host.empty()) {
                UI_WINDOW::UpdateLog("Failed to parse host from HTTP request.");
                
                return;
            }

            // Kiểm tra Blacklist/Whitelist
            if (UI_WINDOW::listType == 0) { // Blacklist
                if (Blacklist::isBlocked(host)) {
                    UI_WINDOW::UpdateLog("Access to " + host + " is blocked.");
                    const char* forbiddenResponse = 
                        "HTTP/1.1 403 Forbidden\r\n"
                        "Connection: close\r\n"
                        "Proxy-Agent: CustomProxy/1.0\r\n"
                        "\r\n";

                    send(clientSocket, forbiddenResponse, strlen(forbiddenResponse), 0);
                    closesocket(clientSocket);
                    return;
                }
            } else { // Whitelist
                if (!Whitelist::isAble(host)) {
                    UI_WINDOW::UpdateLog("Access to " + host + " is not allowed.");
                    const char* forbiddenResponse = 
                        "HTTP/1.1 403 Forbidden\r\n"
                        "Connection: close\r\n"
                        "Proxy-Agent: CustomProxy/1.0\r\n"
                        "\r\n";

                    send(clientSocket, forbiddenResponse, strlen(forbiddenResponse), 0);
                    closesocket(clientSocket);
                    return;
                }
            }

            // Thêm HOST vào danh sách luồng
            {
                threadMap[std::this_thread::get_id()] = std::make_pair(host, request);
                hostRequestMap[host] = request;
                stopFlags[std::this_thread::get_id()] = false; // Đặt cờ dừng ban đầu là false

                printActiveThreads(); // Hiển thị danh sách luồng
            }

            // Kiểm tra xem HOST có bị chặn trong quá trình xử lý
            checkAndStopBlacklistedThreads();  

            activeThreads++;        
    
            int port = 80; // Default HTTP port
            UI_WINDOW::UpdateLog("Handling HTTP request: " + host + ":" + std::to_string(port));

            // Tạo luồng mới để xử lý yêu cầu HTTP
            handleHttpRequest(clientSocket, host, port, request);
            
            activeThreads--;        

            // Xóa luồng khỏi danh sách và đóng kết nối
            {
                std::lock_guard<std::mutex> lock(threadMapMutex);
                hostRequestMap.erase(threadMap[std::this_thread::get_id()].first);
                threadMap.erase(std::this_thread::get_id());
                stopFlags.erase(std::this_thread::get_id());
            }

            printActiveThreads(); // Hiển thị danh sách luồng

            closesocket(clientSocket);

            return;
        }

        // Phân tích yêu cầu CONNECT
        size_t hostStart = request.find(' ') + 1;
        size_t hostEnd = request.find(':', hostStart);
        size_t portEnd = request.find(' ', hostEnd);
        if (hostStart == std::string::npos || hostEnd == std::string::npos || portEnd == std::string::npos) {
            UI_WINDOW::UpdateLog("Malformed CONNECT request.");
            closesocket(clientSocket);
            return;
        }

        std::string host = request.substr(hostStart, hostEnd - hostStart);
        std::string portStr = request.substr(hostEnd + 1, portEnd - hostEnd - 1);

        int port = 0;
        try {
            port = std::stoi(portStr); // Chuyển chuỗi port sang số
        } catch (const std::invalid_argument& e) {
            UI_WINDOW::UpdateLog("Invalid port number format: " + portStr + ", Error: " + std::string(e.what()));
            closesocket(clientSocket);
            return;
        } catch (const std::out_of_range& e) {
            UI_WINDOW::UpdateLog("Port number out of range: " + portStr + ", Error: " + std::string(e.what()));
            closesocket(clientSocket);
            return;
        }

        if (port <= 0 || port > 65535) {
            UI_WINDOW::UpdateLog("Invalid port range: " + std::to_string(port));
            closesocket(clientSocket);
            return;
        }

        if (UI_WINDOW::listType == 0) {
            if (Blacklist::isBlocked(host)) {
                UI_WINDOW::UpdateLog("Access to " + host + " is blocked.");
                const char* forbiddenResponse = 
                    "HTTP/1.1 403 Forbidden\r\n"
                    "Connection: close\r\n"
                    "Proxy-Agent: CustomProxy/1.0\r\n"
                    "\r\n";

                send(clientSocket, forbiddenResponse, strlen(forbiddenResponse), 0);
                closesocket(clientSocket);
                return;
            }
        } else {
            if (not Whitelist::isAble(host)) {
                UI_WINDOW::UpdateLog("Access to " + host + " is not able.");
                const char* forbiddenResponse = 
                    "HTTP/1.1 403 Forbidden\r\n"
                    "Connection: close\r\n"
                    "Proxy-Agent: CustomProxy/1.0\r\n"
                    "\r\n";

                send(clientSocket, forbiddenResponse, strlen(forbiddenResponse), 0);
                closesocket(clientSocket);
                return;
            }
        }
        // Thêm HOST vào danh sách luồng
        {
            threadMap[std::this_thread::get_id()] = std::make_pair(host, request);
            hostRequestMap[host] = request;
            stopFlags[std::this_thread::get_id()] = false; // Đặt cờ dừng ban đầu là false

            printActiveThreads(); // Hiển thị danh sách luồng
        }

        // Checking if the HOST is Blacklisted while handling the client
        checkAndStopBlacklistedThreads();  

        activeThreads++;
        
        UI_WINDOW::UpdateLog("Connecting: " + host + ":" + std::to_string(port));
        handleConnectMethod(clientSocket, host, port);
        
        activeThreads--;

        // Xóa luồng khỏi danh sách và đóng kết nối
        {
            std::lock_guard<std::mutex> lock(threadMapMutex);
            hostRequestMap.erase(threadMap[std::this_thread::get_id()].first);
            threadMap.erase(std::this_thread::get_id());
            stopFlags.erase(std::this_thread::get_id());
        }

        printActiveThreads(); // Hiển thị danh sách luồng

        closesocket(clientSocket);
    }
}