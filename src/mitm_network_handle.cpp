#include "mitm_network_handle.h"

namespace MITMNetworkHandle {
    std::atomic<int> activeThreads(0); // Quản lý các luồng đang hoạt động
    std::map<std::thread::id, std::tuple<std::string, std::string, std::string>> threadMap;
    std::mutex threadMapMutex; // Mutex để đồng bộ
    std::map<std::thread::id, std::atomic<bool>> stopFlags; // Cờ dừng cho từng luồng

    std::map<std::string, std::string> hostRequestMap;

    // SSL_CTX cố định cho proxy
    EVP_PKEY* caKey;
    X509* caCert;
    SSL_CTX* global_ssl_ctx = nullptr;

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
        for (auto& [id, data] : threadMap) {
            if (UI_WINDOW::listType == 0) {
                if (Blacklist::isBlocked(std::get<1>(data))) {
                    stopFlags[id] = true;  // Set flag to true to stop the thread
                }
            } else {
                if (not Whitelist::isAble(std::get<1>(data))) {
                    stopFlags[id] = true;
                }
            }
        }
    }

    std::string forbiddenResponse(const std::string& host) {
        std::string body = 
            "<html>"
            "<head>"
            "<title>403 Forbidden</title>"
            "<style>"
            "body { font-family: Arial, sans-serif; text-align: center; margin: 0; padding: 0; display: flex; flex-direction: column; justify-content: center; align-items: center; height: 100vh; background-color: #f8f8f8; }"
            "h1 { color: #ff0000; }"
            "p { color: #333333; font-size: 16px; }"
            "button { margin-top: 20px; padding: 10px 20px; font-size: 16px; color: #fff; background-color: #007bff; border: none; border-radius: 5px; cursor: pointer; }"
            "button:hover { background-color: #0056b3; }"
            "</style>"
            "</head>"
            "<body>"
            "<h1>403 Forbidden</h1>"
            "<p>Access to <strong>" + host + "</strong> is denied.</p>"
            "<p>If you believe this is an error, please contact the administrator.</p>"
            "<button onclick=\"location.reload()\">Reload</button>"
            "</body>"
            "</html>";

        std::string forbiddenResponse = 
            "HTTP/1.1 403 Forbidden\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: " + std::to_string(body.size()) + "\r\n"
            "Connection: close\r\n"
            "Proxy-Agent: CustomProxy/1.0\r\n"
            "\r\n" + body;
        
        return forbiddenResponse;
    }

    void initializeOpenSSL() {
        SSL_library_init();
        SSL_load_error_strings();
        OpenSSL_add_all_algorithms();
        ERR_load_BIO_strings();
        ERR_load_crypto_strings();
        OpenSSL_add_all_ciphers();
        OpenSSL_add_all_digests();
    }

    void cleanupOpenSSL() {
        EVP_cleanup();
        ERR_free_strings();
        // Không cần gọi các hàm giải phóng khác vì OpenSSL tự động quản lý tài nguyên sau khi chương trình kết thúc
    }

    // Hàm tạo khóa RSA mới sử dụng EVP API
    EVP_PKEY* generateRSAKey() {
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
        if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0) {
            std::cerr << "Failed to initialize keygen context.\n";
            return nullptr;
        }
        if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) {
            std::cerr << "Failed to set RSA key length.\n";
            return nullptr;
        }
        EVP_PKEY* pkey = nullptr;
        if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
            std::cerr << "Failed to generate RSA key.\n";
            return nullptr;
        }
        return pkey;
    }

    std::pair<X509*, EVP_PKEY*> generateCertificate(EVP_PKEY* caKey, X509* caCert, const std::string& domain) {
        X509* cert = X509_new();
        if (!cert) {
            std::cerr << "Unable to create X509 certificate.\n";
            return {nullptr, nullptr};
        }

        X509_set_version(cert, 2);
        ASN1_INTEGER_set(X509_get_serialNumber(cert), rand());
        X509_gmtime_adj(X509_get_notBefore(cert), 0);
        X509_gmtime_adj(X509_get_notAfter(cert), 365 * 24 * 60 * 60);

        // Tạo cặp khóa RSA cho chứng chỉ mới
        EVP_PKEY* subKey = generateRSAKey();
        if (!subKey) {
            std::cerr << "Failed to generate RSA key for certificate.\n";
            return {nullptr, nullptr};
        }

        // Gắn khóa công khai của subKey vào chứng chỉ
        if (X509_set_pubkey(cert, subKey) <= 0) {
            unsigned long err = ERR_get_error();
            std::cerr << "Failed to attach public key to certificate. OpenSSL Error: " << ERR_error_string(err, NULL) << "\n";
            return {nullptr, nullptr};
        }

         // Thiết lập Subject và Issuer name
        X509_NAME* name = X509_get_subject_name(cert);

        // Correctly set the subject name:
        X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (const unsigned char*)"VN", -1, -1, 0);
        X509_NAME_add_entry_by_txt(name, "ST", MBSTRING_ASC, (const unsigned char*)"Ho Chi Minh", -1, -1, 0);
        X509_NAME_add_entry_by_txt(name, "L", MBSTRING_ASC, (const unsigned char*)"Ho Chi Minh City", -1, -1, 0);
        X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (const unsigned char*)"MyProxy Vietnam", -1, -1, 0);
        X509_NAME_add_entry_by_txt(name, "OU", MBSTRING_ASC, (const unsigned char*)"IT Department", -1, -1, 0);
        X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char*)domain.c_str(), -1, -1, 0);
        X509_NAME_add_entry_by_txt(name, "emailAddress", MBSTRING_ASC, (const unsigned char*)"phanngung77x17@gmail.com", -1, -1, 0);

        if (!caCert) {
            std::cerr << "Root CA certificate is null.\n";
            return {nullptr, nullptr};
        }

        if (X509_set_issuer_name(cert, X509_get_subject_name(caCert)) <= 0) {
            std::cerr << "Failed to set issuer name.\n";
            return {nullptr, nullptr};
        }

        // Ký chứng chỉ với rootCA key
        if (X509_sign(cert, caKey, EVP_sha256()) <= 0) {
            unsigned long err = ERR_get_error();
            std::cerr << "Failed to sign certificate. OpenSSL Error: " << ERR_error_string(err, NULL) << "\n";
            return {nullptr, nullptr};
        }

        return {cert, subKey};
    }

    void handleSSLConnection(SOCKET clientSocket, const std::string& host, int port, SSL_CTX* ctx, const std::string& clientIP) {
        // Kiểm tra SSL_CTX
        if (!caKey || !caCert) {
            UI_WINDOW::UpdateLog("CA key or certificate is null.", clientIP);
            closesocket(clientSocket);
            return;
        }

        if (!ctx) {
            UI_WINDOW::UpdateLog("Invalid SSL_CTX provided.", clientIP);
            closesocket(clientSocket);
            return;
        }

        // Tạo chứng chỉ con cho domain
        auto [cert, subKey] = generateCertificate(caKey, caCert, host);
        if (!cert || !subKey) {
            UI_WINDOW::UpdateLog("Failed to generate certificate for host: " + host, clientIP);
            closesocket(clientSocket);
            return;
        }

        // Tạo SSL_CTX mới cho chứng chỉ động
        SSL_CTX* childCtx = SSL_CTX_new(TLS_server_method());
        if (!childCtx) {
            UI_WINDOW::UpdateLog("Failed to create SSL_CTX for child connection.", clientIP);
            closesocket(clientSocket);
            return;
        }

        if (SSL_CTX_use_certificate(childCtx, cert) <= 0) {
            UI_WINDOW::UpdateLog("Failed to use certificate in SSL_CTX.", clientIP);
            unsigned long err = ERR_get_error();
            UI_WINDOW::UpdateLog("OpenSSL Error: " + std::string(ERR_error_string(err, NULL)), clientIP);
            closesocket(clientSocket);
            return;
        }

        // if (SSL_CTX_add_extra_chain_cert(childCtx, caCert) <= 0) {
        //     UI_WINDOW::UpdateLog("Failed to add root CA certificate to chain.", clientIP);
        //     closesocket(clientSocket);
        //     return;
        // }

        if (SSL_CTX_use_PrivateKey(childCtx, subKey) <= 0) {
            UI_WINDOW::UpdateLog("Failed to use private key in SSL_CTX.", clientIP);
            unsigned long err = ERR_get_error();
            UI_WINDOW::UpdateLog("OpenSSL Error: " + std::string(ERR_error_string(err, NULL)), clientIP);
            closesocket(clientSocket);
            return;
        }

        if (!SSL_CTX_check_private_key(childCtx)) {
            UI_WINDOW::UpdateLog("Private key does not match the certificate public key.", clientIP);
            closesocket(clientSocket);
            return;
        }

        // Tạo SSL object
        SSL* ssl = SSL_new(childCtx);
        if (!ssl) {
            UI_WINDOW::UpdateLog("Failed to create SSL object.", clientIP);
            closesocket(clientSocket);
            return;
        }

        SSL_set_fd(ssl, clientSocket);

        // Thực hiện SSL handshake
        if (SSL_accept(ssl) <= 0) {
            int error = SSL_get_error(ssl, -1);
            unsigned long err = ERR_get_error();
            UI_WINDOW::UpdateLog("SSL handshake failed. SSL Error: " + std::to_string(error) +
                                ", OpenSSL Details: " + std::string(ERR_error_string(err, NULL)), clientIP);
            closesocket(clientSocket);
            return;
        }

        UI_WINDOW::UpdateLog("SSL handshake with client succeeded.", clientIP);

        // Tạo kết nối đến server thật
        SOCKET remoteSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (remoteSocket == INVALID_SOCKET) {
            UI_WINDOW::UpdateLog("Cannot create remote socket.", clientIP);
            closesocket(clientSocket);
            return;
        }

        sockaddr_in serverAddr;
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_port = htons(port);
        struct hostent* remoteHost = gethostbyname(host.c_str());
        if (remoteHost == NULL) {
            UI_WINDOW::UpdateLog("Cannot resolve hostname.", clientIP);
            closesocket(remoteSocket);
            closesocket(clientSocket);
            return;
        }
        memcpy(&serverAddr.sin_addr.s_addr, remoteHost->h_addr, remoteHost->h_length);

        if (connect(remoteSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
            UI_WINDOW::UpdateLog("Cannot connect to remote server.", clientIP);
            closesocket(remoteSocket);
            closesocket(clientSocket);
            return;
        }

        UI_WINDOW::UpdateLog("Connected to remote server.", clientIP);

        // Khởi tạo SSL cho kết nối đến server
        SSL_CTX* serverCtx = SSL_CTX_new(TLS_client_method());
        if (!serverCtx) {
            UI_WINDOW::UpdateLog("Unable to create server SSL context.", clientIP);
            closesocket(remoteSocket);
            closesocket(clientSocket);
            return;
        }

        // Thiết lập các tùy chọn SSL_CTX cho server
        SSL_CTX_set_min_proto_version(serverCtx, TLS1_2_VERSION);
        SSL_CTX_set_max_proto_version(serverCtx, TLS1_3_VERSION);
        SSL_CTX_set_cipher_list(serverCtx, "HIGH:!aNULL:!MD5");

        // Tạo SSL object cho server
        SSL* sslServer = SSL_new(serverCtx);
        if (!sslServer) {
            UI_WINDOW::UpdateLog("Failed to create SSL object for server.", clientIP);
            closesocket(remoteSocket);
            closesocket(clientSocket);
            return;
        }

        SSL_set_fd(sslServer, remoteSocket);

        // Thực hiện SSL handshake với server
        if (SSL_connect(sslServer) <= 0) {
            int error = SSL_get_error(sslServer, -1);
            unsigned long err = ERR_get_error();
            UI_WINDOW::UpdateLog("SSL handshake failed with server. SSL Error: " + std::to_string(error) +
                ", OpenSSL Details: " + std::string(ERR_error_string(err, NULL)), clientIP);
            closesocket(remoteSocket);
            closesocket(clientSocket);
            return;
        }

        UI_WINDOW::UpdateLog("SSL handshake with server succeeded.", clientIP);

        // Chuyển dữ liệu giữa client và server
        fd_set readfds;
        char buffer[BUFFER_SIZE];
        bool connectionOpen = true;
        while (connectionOpen) {
            if (UI_WINDOW::isProxyRunning == false) {
                UI_WINDOW::UpdateLog("Disconnecting: " + host + " || Reason: Stopped proxy.", clientIP);
                break;
            }
            FD_ZERO(&readfds);
            FD_SET(clientSocket, &readfds);
            FD_SET(remoteSocket, &readfds);

            struct timeval timeout;
            timeout.tv_sec = 30; // Tăng timeout lên 30 giây
            timeout.tv_usec = 0;

            int maxfd = (clientSocket > remoteSocket) ? clientSocket : remoteSocket;
            int activity = select(maxfd + 1, &readfds, NULL, NULL, &timeout);
            if (activity < 0) {
                UI_WINDOW::UpdateLog("Select error.", clientIP);
                break;
            }
            if (activity == 0) {
                UI_WINDOW::UpdateLog("Disconnecting: " + host + " || Reason: Timeout occurred, closing connection.", clientIP);
                break;
            }

            if (FD_ISSET(clientSocket, &readfds)) {
                int receivedBytes = SSL_read(ssl, buffer, sizeof(buffer));
                if (receivedBytes <= 0) {
                    connectionOpen = false;
                    break;
                }

                // Log dữ liệu từ client
                std::string data(buffer, receivedBytes);
                // UI_WINDOW::LogData("Client -> Server:", data);

                if (SSL_write(sslServer, buffer, receivedBytes) <= 0) {
                    connectionOpen = false;
                    break;
                }
            }
            if (FD_ISSET(remoteSocket, &readfds)) {
                int receivedBytes = SSL_read(sslServer, buffer, sizeof(buffer));
                if (receivedBytes <= 0) {
                    connectionOpen = false;
                    break;
                }

                // Log dữ liệu từ server
                std::string data(buffer, receivedBytes);
                UI_WINDOW::LogData("Server -> Client:", data, clientIP);

                if (SSL_write(ssl, buffer, receivedBytes) <= 0) {
                    connectionOpen = false;
                    break;
                }
            }
        }

        // Đóng kết nối SSL và các tài nguyên
        SSL_free(ssl);
        SSL_free(sslServer);
        SSL_CTX_free(serverCtx);
        closesocket(remoteSocket);
        closesocket(clientSocket);
    }

    void handleHttpRequest(SOCKET clientSocket, const std::string& host, int port, const std::string& request, const std::string& clientIP) {
        // Kết nối đến server thật
        SOCKET remoteSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (remoteSocket == INVALID_SOCKET) {
            UI_WINDOW::UpdateLog("Cannot create remote socket.", clientIP);
            
            return;
        }

        sockaddr_in serverAddr;
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_port = htons(port);
        struct hostent* remoteHost = gethostbyname(host.c_str());
        if (remoteHost == NULL) {
            UI_WINDOW::UpdateLog("Cannot resolve hostname: " + host, clientIP);
            closesocket(remoteSocket);
            
            return;
        }
        memcpy(&serverAddr.sin_addr.s_addr, remoteHost->h_addr, remoteHost->h_length);

        if (connect(remoteSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
            UI_WINDOW::UpdateLog("Cannot connect to remote server: " + host + ":" + std::to_string(port), clientIP);
            closesocket(remoteSocket);
            
            return;
        }

        UI_WINDOW::UpdateLog("Connected to remote server for HTTP request: " + host + ":" + std::to_string(port), clientIP);

        // Gửi yêu cầu đến server
        send(remoteSocket, request.c_str(), request.size(), 0);

        // Relay dữ liệu từ server tới client
        fd_set readfds;
        char buffer_data[BUFFER_SIZE];
        bool connectionOpen = true;
        while (connectionOpen and not stopFlags[std::this_thread::get_id()]) {
            FD_ZERO(&readfds);
            FD_SET(clientSocket, &readfds);
            FD_SET(remoteSocket, &readfds);

            struct timeval timeout;
            timeout.tv_sec = 30;
            timeout.tv_usec = 0;

            int maxfd = (clientSocket > remoteSocket) ? clientSocket : remoteSocket;
            int activity = select(maxfd + 1, &readfds, NULL, NULL, &timeout);
            if (activity < 0) {
                UI_WINDOW::UpdateLog("Select error in HTTP request handling.", clientIP);
                break;
            }
            if (activity == 0) {
                UI_WINDOW::UpdateLog("Timeout occurred, closing HTTP connection.", clientIP);
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
                UI_WINDOW::LogData("Server -> Client:", data, clientIP);

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
                UI_WINDOW::LogData("Client -> Server:", data, clientIP);

                // Gửi dữ liệu tới server
                send(remoteSocket, buffer_data, receivedBytes, 0);
            }
        }

        // Đóng kết nối
        closesocket(remoteSocket);

        if (stopFlags[std::this_thread::get_id()]) {
            std::string message = forbiddenResponse(host);
            send(clientSocket, message.c_str(), message.size(), 0);
            closesocket(clientSocket);
            return;
        }
    }

    void handleClient(SOCKET clientSocket) {
        sockaddr_in clientAddr;
        int clientAddrSize = sizeof(clientAddr);
        if (getpeername(clientSocket, (struct sockaddr*)&clientAddr, &clientAddrSize) != 0) {
            UI_WINDOW::UpdateLog("Fail to get clientSocket IP", std::string());
            return;
        }
        char clientIP[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &clientAddr.sin_addr, clientIP, INET_ADDRSTRLEN);

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
                UI_WINDOW::UpdateLog("Failed to parse host from HTTP request.", clientIP);
                
                return;
            }

            // Kiểm tra Blacklist/Whitelist
            if (UI_WINDOW::listType == 0) { // Blacklist
                if (Blacklist::isBlocked(host)) {
                    UI_WINDOW::UpdateLog("Access to " + host + " is blocked.", clientIP);
                    std::string message = forbiddenResponse(host);
                    send(clientSocket, message.c_str(), message.size(), 0);
                    closesocket(clientSocket);
                    return;
                }
            } else { // Whitelist
                if (!Whitelist::isAble(host)) {
                    UI_WINDOW::UpdateLog("Access to " + host + " is not allowed.", clientIP);
                    std::string message = forbiddenResponse(host);
                    send(clientSocket, message.c_str(), message.size(), 0);
                    closesocket(clientSocket);
                    return;
                }
            }

            // Thêm HOST vào danh sách luồng
            {
                threadMap[std::this_thread::get_id()] = std::make_tuple(clientIP, host, request);
                hostRequestMap[(std::string)clientIP + (std::string)" - " + host] = request;
                stopFlags[std::this_thread::get_id()] = false; // Đặt cờ dừng ban đầu là false

                printActiveThreads(); // Hiển thị danh sách luồng
            }

            activeThreads++;        
    
            int port = 80; // Default HTTP port
            UI_WINDOW::UpdateLog("Handling HTTP request: " + host + ":" + std::to_string(port), clientIP);

            // Tạo luồng mới để xử lý yêu cầu HTTP
            handleHttpRequest(clientSocket, host, port, request, clientIP);
            
            activeThreads--;        

            // Xóa luồng khỏi danh sách và đóng kết nối
            {
                std::lock_guard<std::mutex> lock(threadMapMutex);
                hostRequestMap.erase(std::get<0>(threadMap[std::this_thread::get_id()]) + (std::string)" - " + std::get<1>(threadMap[std::this_thread::get_id()]));
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
            UI_WINDOW::UpdateLog("Malformed CONNECT request.", clientIP);
            closesocket(clientSocket);
            return;
        }

        std::string host = request.substr(hostStart, hostEnd - hostStart);
        std::string portStr = request.substr(hostEnd + 1, portEnd - hostEnd - 1);

        int port = 0;
        try {
            port = std::stoi(portStr); // Chuyển chuỗi port sang số
        } catch (const std::invalid_argument& e) {
            UI_WINDOW::UpdateLog("Invalid port number format: " + portStr + ", Error: " + std::string(e.what()), clientIP);
            closesocket(clientSocket);
            return;
        } catch (const std::out_of_range& e) {
            UI_WINDOW::UpdateLog("Port number out of range: " + portStr + ", Error: " + std::string(e.what()), clientIP);
            closesocket(clientSocket);
            return;
        }

        if (port <= 0 || port > 65535) {
            UI_WINDOW::UpdateLog("Invalid port range: " + std::to_string(port), clientIP);
            closesocket(clientSocket);
            return;
        }

        // Kiểm tra Blacklist/Whitelist
        if (UI_WINDOW::listType == 0) { // Blacklist
            if (Blacklist::isBlocked(host)) {
                UI_WINDOW::UpdateLog("Access to " + host + " is blocked.", clientIP);
                std::string message = forbiddenResponse(host);
                send(clientSocket, message.c_str(), message.size(), 0);
                closesocket(clientSocket);
                return;
            }
        } else { // Whitelist
            if (!Whitelist::isAble(host)) {
                UI_WINDOW::UpdateLog("Access to " + host + " is not allowed.", clientIP);
                std::string message = forbiddenResponse(host);
                send(clientSocket, message.c_str(), message.size(), 0);
                closesocket(clientSocket);
                return;
            }
        }

        // Thêm HOST vào danh sách luồng
        {
            threadMap[std::this_thread::get_id()] = std::make_tuple(clientIP, host, request);
            hostRequestMap[(std::string)clientIP + (std::string)" - " + host] = request;
            stopFlags[std::this_thread::get_id()] = false; // Đặt cờ dừng ban đầu là false

            printActiveThreads(); // Hiển thị danh sách luồng
        }

        activeThreads++;

        UI_WINDOW::UpdateLog("Connecting: " + host + ":" + std::to_string(port), clientIP);
        handleSSLConnection(clientSocket, host, port, global_ssl_ctx, clientIP);

        activeThreads--;

        // Xóa luồng khỏi danh sách và đóng kết nối
        {
            std::lock_guard<std::mutex> lock(threadMapMutex);
            hostRequestMap.erase(std::get<0>(threadMap[std::this_thread::get_id()]) + (std::string)" - " + std::get<1>(threadMap[std::this_thread::get_id()]));
            threadMap.erase(std::this_thread::get_id());
            stopFlags.erase(std::this_thread::get_id());
        }

        printActiveThreads(); // Hiển thị danh sách luồng

        closesocket(clientSocket);
    }
}