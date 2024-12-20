#include "network_handle.h"

EVP_PKEY* caKey;
X509* caCert;

namespace MITMNetworkHandle {
    // Biến toàn cục
    std::atomic<int> activeThreads(0); // Quản lý các luồng đang hoạt động
    std::map<std::thread::id, std::pair<std::string, std::string>> threadMap; // Danh sách luồng và URL
    std::mutex threadMapMutex; // Mutex để đồng bộ
    std::map<std::thread::id, std::atomic<bool>> stopFlags; // Cờ dừng cho từng luồng

    std::map<std::string, std::string> hostRequestMap;

    // SSL_CTX cố định cho proxy
    SSL_CTX* global_ssl_ctx = nullptr;

    std::string parseHttpRequest(const std::string& request) {
        size_t pos = request.find("Host: ");
        if (pos == std::string::npos) return std::string();

        size_t start = pos + 6;
        size_t end = request.find("\r\n", start);
        if (end == std::string::npos) return std::string();

        return request.substr(start, end - start);
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
        EVP_PKEY* pkey = nullptr;
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
        if (!ctx) {
            std::cerr << "Failed to create EVP_PKEY_CTX.\n";
            return nullptr;
        }

        if (EVP_PKEY_keygen_init(ctx) <= 0) {
            std::cerr << "Failed to initialize keygen context.\n";
            EVP_PKEY_CTX_free(ctx);
            return nullptr;
        }

        if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) {
            std::cerr << "Failed to set RSA key length.\n";
            EVP_PKEY_CTX_free(ctx);
            return nullptr;
        }

        if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
            std::cerr << "Failed to generate RSA key.\n";
            EVP_PKEY_CTX_free(ctx);
            return nullptr;
        }

        EVP_PKEY_CTX_free(ctx);
        return pkey;
    }

    // Hàm tạo chứng chỉ tự ký với các phần mở rộng cần thiết
    X509* generateSelfSignedCert(EVP_PKEY* pkey, const std::string& host) {
        X509* cert = X509_new();
        if (!cert) {
            std::cerr << "Unable to create X509 certificate.\n";
            return nullptr;
        }

        // Đặt phiên bản chứng chỉ (X509v3)
        X509_set_version(cert, 2);

        // Tạo số serial duy nhất
        ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);

        // Đặt thời gian hiệu lực của chứng chỉ
        X509_gmtime_adj(X509_get_notBefore(cert), 0);
        X509_gmtime_adj(X509_get_notAfter(cert), 365 * 24 * 60 * 60); // 1 năm

        // Gắn khóa công khai vào chứng chỉ
        if (X509_set_pubkey(cert, pkey) <= 0) {
            std::cerr << "Failed to set public key in certificate.\n";
            X509_free(cert);
            return nullptr;
        }

        // Đặt Subject và Issuer name
        X509_NAME* name = X509_get_subject_name(cert);
        if (!name) {
            std::cerr << "Failed to get subject name from certificate.\n";
            X509_free(cert);
            return nullptr;
        }

        // Thêm các trường vào Subject name
        X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC,
                                reinterpret_cast<const unsigned char*>("US"), -1, -1, 0);
        X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC,
                                reinterpret_cast<const unsigned char*>("MyProxy"), -1, -1, 0);
        X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                reinterpret_cast<const unsigned char*>(host.c_str()), -1, -1, 0);

        // Đặt Issuer name giống Subject name (self-signed)
        if (X509_set_issuer_name(cert, name) <= 0) {
            std::cerr << "Failed to set issuer name.\n";
            X509_free(cert);
            return nullptr;
        }

        // Thêm các phần mở rộng vào chứng chỉ
        X509_EXTENSION* ext;

        // Basic Constraints: CA:TRUE
        ext = X509V3_EXT_conf_nid(nullptr, nullptr, NID_basic_constraints, "CA:TRUE");
        if (!ext) {
            std::cerr << "Failed to create Basic Constraints extension.\n";
            X509_free(cert);
            return nullptr;
        }
        X509_add_ext(cert, ext, -1);
        X509_EXTENSION_free(ext);

        // Key Usage: Digital Signature, Key Encipherment
        ext = X509V3_EXT_conf_nid(nullptr, nullptr, NID_key_usage, "digitalSignature,keyEncipherment,keyCertSign");
        if (!ext) {
            std::cerr << "Failed to create Key Usage extension.\n";
            X509_free(cert);
            return nullptr;
        }
        X509_add_ext(cert, ext, -1);
        X509_EXTENSION_free(ext);

        // Extended Key Usage: Server Authentication
        ext = X509V3_EXT_conf_nid(nullptr, nullptr, NID_ext_key_usage, "serverAuth");
        if (!ext) {
            std::cerr << "Failed to create Extended Key Usage extension.\n";
            X509_free(cert);
            return nullptr;
        }
        X509_add_ext(cert, ext, -1);
        X509_EXTENSION_free(ext);

        // Subject Alternative Name: DNS:host
        std::string san = "DNS:" + host;
        ext = X509V3_EXT_conf_nid(nullptr, nullptr, NID_subject_alt_name, san.c_str());
        if (!ext) {
            std::cerr << "Failed to create Subject Alternative Name extension.\n";
            X509_free(cert);
            return nullptr;
        }
        X509_add_ext(cert, ext, -1);
        X509_EXTENSION_free(ext);

        // Ký chứng chỉ
        if (X509_sign(cert, pkey, EVP_sha256()) <= 0) {
            std::cerr << "Failed to sign certificate.\n";
            X509_free(cert);
            return nullptr;
        }

        return cert;
    }

    // Hàm ghi chứng chỉ vào tệp (dùng để cài đặt vào client nếu cần)
    bool writeCertToFile(X509* cert, const std::string& filename) {
        FILE* certFile = fopen(filename.c_str(), "wb");
        if (!certFile) {
            std::cerr << "Failed to open file to write certificate.\n";
            return false;
        }
        if (!PEM_write_X509(certFile, cert)) {
            std::cerr << "Failed to write certificate to file.\n";
            fclose(certFile);
            return false;
        }
        fclose(certFile);
        return true;
    }

    // Function to create a fake SSL context with a self-signed certificate
    SSL_CTX* createFakeSSLContext(EVP_PKEY* pkey, X509* cert) {
        // Tạo SSL Context
        SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
        if (!ctx) {
            UI_WINDOW::UpdateLog("Unable to create SSL context.");
            return nullptr;
        }

        // Gắn chứng chỉ và khóa vào SSL_CTX
        if (SSL_CTX_use_certificate(ctx, cert) <= 0) {
            UI_WINDOW::UpdateLog("Failed to use certificate in SSL context.");
            X509_free(cert);
            EVP_PKEY_free(pkey);
            SSL_CTX_free(ctx);
            return nullptr;
        }

        if (SSL_CTX_use_PrivateKey(ctx, pkey) <= 0) {
            UI_WINDOW::UpdateLog("Failed to use private key in SSL context.");
            X509_free(cert);
            EVP_PKEY_free(pkey);
            SSL_CTX_free(ctx);
            return nullptr;
        }

        // Kiểm tra khóa và chứng chỉ
        if (!SSL_CTX_check_private_key(ctx)) {
            UI_WINDOW::UpdateLog("Private key does not match the public certificate.");
            X509_free(cert);
            EVP_PKEY_free(pkey);
            SSL_CTX_free(ctx);
            return nullptr;
        }

        // Thiết lập các tùy chọn SSL_CTX
        SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
        SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
        SSL_CTX_set_cipher_list(ctx, "HIGH:!aNULL:!MD5");

        // Bật ghi log chi tiết cho SSL
        SSL_CTX_set_info_callback(ctx, [](const SSL* ssl, int where, int ret) {
            if (where & SSL_CB_HANDSHAKE_START) {
                std::cerr << "SSL Handshake started.\n";
            }
            if (where & SSL_CB_HANDSHAKE_DONE) {
                std::cerr << "SSL Handshake done.\n";
            }
            if (where & SSL_CB_ALERT) {
                const char* alertType = SSL_alert_type_string(ret);
                const char* alertDesc = SSL_alert_desc_string(ret);
                std::cerr << "SSL Alert - Type: " << (alertType ? alertType : "unknown")
                        << ", Description: " << (alertDesc ? alertDesc : "unknown") << "\n";
            }
            if (where & SSL_CB_EXIT) {
                if (ret == 0) {
                    unsigned long err = ERR_get_error();
                    std::cerr << "SSL Error: " << ERR_error_string(err, NULL) << "\n";
                }
            }
        });

        return ctx;
    }

    X509* generateCertificate(EVP_PKEY* caKey, X509* caCert, const std::string& domain) {
        X509* cert = X509_new();
        if (!cert) {
            std::cerr << "Unable to create X509 certificate.\n";
            return nullptr;
        }

        X509_set_version(cert, 2);
        ASN1_INTEGER_set(X509_get_serialNumber(cert), rand());
        X509_gmtime_adj(X509_get_notBefore(cert), 0);
        X509_gmtime_adj(X509_get_notAfter(cert), 365 * 24 * 60 * 60);

        EVP_PKEY* subKey = generateRSAKey();
        if (!subKey) {
            std::cerr << "Failed to generate RSA key for certificate.\n";
            X509_free(cert);
            return nullptr;
        }

        if (X509_set_pubkey(cert, subKey) <= 0) {
            unsigned long err = ERR_get_error();
            std::cerr << "Failed to attach public key to certificate. OpenSSL Error: " << ERR_error_string(err, NULL) << "\n";
            EVP_PKEY_free(subKey);
            X509_free(cert);
            return nullptr;
        }

        X509_NAME* name = X509_get_subject_name(cert);
        if (!name) {
            std::cerr << "Failed to get subject name from certificate.\n";
            EVP_PKEY_free(subKey);
            X509_free(cert);
            return nullptr;
        }

        X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char*>(domain.c_str()), -1, -1, 0);
        X509_set_issuer_name(cert, X509_get_subject_name(caCert));

        if (X509_sign(cert, caKey, EVP_sha256()) <= 0) {
            unsigned long err = ERR_get_error();
            std::cerr << "Failed to sign certificate. OpenSSL Error: " << ERR_error_string(err, NULL) << "\n";
            EVP_PKEY_free(subKey);
            X509_free(cert);
            return nullptr;
        }

        EVP_PKEY_free(subKey);
        return cert;
    }

    void handleSSLConnection(SOCKET clientSocket, const std::string& host, int port, SSL_CTX* ctx) {
        // Kiểm tra SSL_CTX
        if (!caKey || !caCert) {
            UI_WINDOW::UpdateLog("CA key or certificate is null.");
            closesocket(clientSocket);
            return;
        }

        if (!ctx) {
            UI_WINDOW::UpdateLog("Invalid SSL_CTX provided.");
            closesocket(clientSocket);
            return;
        }

        // Tạo chứng chỉ con cho domain
        X509* cert = generateCertificate(caKey, caCert, host);
        if (!cert) {
            UI_WINDOW::UpdateLog("Failed to generate certificate for host: " + host);
            closesocket(clientSocket);
            return;
        }

        // Tạo SSL_CTX mới cho chứng chỉ con
        SSL_CTX* childCtx = SSL_CTX_new(TLS_server_method());
        if (!childCtx) {
            UI_WINDOW::UpdateLog("Failed to create SSL_CTX for child connection.");
            X509_free(cert);
            closesocket(clientSocket);
            return;
        }

        if (SSL_CTX_use_certificate(childCtx, cert) <= 0) {
            UI_WINDOW::UpdateLog("Failed to use certificate in SSL_CTX.");
            unsigned long err = ERR_get_error();
            UI_WINDOW::UpdateLog("OpenSSL Error: " + std::string(ERR_error_string(err, NULL)));
            SSL_CTX_free(childCtx);
            X509_free(cert);
            closesocket(clientSocket);
            return;
        }

        if (SSL_CTX_use_PrivateKey(childCtx, caKey) <= 0) {
            UI_WINDOW::UpdateLog("Failed to use private key in SSL_CTX.");
            unsigned long err = ERR_get_error();
            UI_WINDOW::UpdateLog("OpenSSL Error: " + std::string(ERR_error_string(err, NULL)));
            SSL_CTX_free(childCtx);
            X509_free(cert);
            closesocket(clientSocket);
            return;
        }

        if (!SSL_CTX_check_private_key(childCtx)) {
            UI_WINDOW::UpdateLog("Private key does not match the certificate public key.");
            SSL_CTX_free(childCtx);
            X509_free(cert);
            closesocket(clientSocket);
            return;
        }

        // Tạo SSL object
        SSL* ssl = SSL_new(childCtx);
        if (!ssl) {
            UI_WINDOW::UpdateLog("Failed to create SSL object.");
            SSL_CTX_free(childCtx);
            X509_free(cert);
            closesocket(clientSocket);
            return;
        }

        SSL_set_fd(ssl, clientSocket);

        // Thực hiện SSL handshake
        if (SSL_accept(ssl) <= 0) {
            int error = SSL_get_error(ssl, -1);
            unsigned long err = ERR_get_error();
            UI_WINDOW::UpdateLog("SSL handshake failed. SSL Error: " + std::to_string(error) +
                                ", OpenSSL Details: " + std::string(ERR_error_string(err, NULL)));
            SSL_free(ssl);
            SSL_CTX_free(childCtx);
            X509_free(cert);
            closesocket(clientSocket);
            return;
        }

        UI_WINDOW::UpdateLog("SSL handshake with client succeeded.");

        // Tạo kết nối đến server thật
        SOCKET remoteSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (remoteSocket == INVALID_SOCKET) {
            UI_WINDOW::UpdateLog("Cannot create remote socket.");
            SSL_free(ssl);
            closesocket(clientSocket);
            return;
        }

        sockaddr_in serverAddr;
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_port = htons(port);
        struct hostent* remoteHost = gethostbyname(host.c_str());
        if (remoteHost == NULL) {
            UI_WINDOW::UpdateLog("Cannot resolve hostname.");
            closesocket(remoteSocket);
            SSL_free(ssl);
            closesocket(clientSocket);
            return;
        }
        memcpy(&serverAddr.sin_addr.s_addr, remoteHost->h_addr, remoteHost->h_length);

        if (connect(remoteSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
            UI_WINDOW::UpdateLog("Cannot connect to remote server.");
            closesocket(remoteSocket);
            SSL_free(ssl);
            closesocket(clientSocket);
            return;
        }

        UI_WINDOW::UpdateLog("Connected to remote server.");

        // Khởi tạo SSL cho kết nối đến server
        SSL_CTX* serverCtx = SSL_CTX_new(TLS_client_method());
        if (!serverCtx) {
            UI_WINDOW::UpdateLog("Unable to create server SSL context.");
            closesocket(remoteSocket);
            SSL_free(ssl);
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
            UI_WINDOW::UpdateLog("Failed to create SSL object for server.");
            SSL_CTX_free(serverCtx);
            closesocket(remoteSocket);
            SSL_free(ssl);
            closesocket(clientSocket);
            return;
        }

        SSL_set_fd(sslServer, remoteSocket);

        // Thực hiện SSL handshake với server
        if (SSL_connect(sslServer) <= 0) {
            int error = SSL_get_error(sslServer, -1);
            unsigned long err = ERR_get_error();
            UI_WINDOW::UpdateLog("SSL handshake failed with server. SSL Error: " + std::to_string(error) +
                ", OpenSSL Details: " + std::string(ERR_error_string(err, NULL)));
            SSL_free(ssl);
            SSL_free(sslServer);
            SSL_CTX_free(serverCtx);
            closesocket(remoteSocket);
            closesocket(clientSocket);
            return;
        }

        UI_WINDOW::UpdateLog("SSL handshake with server succeeded.");

        // Chuyển dữ liệu giữa client và server
        fd_set readfds;
        char buffer[BUFFER_SIZE];
        bool connectionOpen = true;
        while (connectionOpen) {
            if (UI_WINDOW::isProxyRunning == false) {
                UI_WINDOW::UpdateLog("Disconnecting: " + host + " || Reason: Stopped proxy.");
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
                UI_WINDOW::UpdateLog("Select error.");
                break;
            }
            if (activity == 0) {
                UI_WINDOW::UpdateLog("Disconnecting: " + host + " || Reason: Timeout occurred, closing connection.");
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
                UI_WINDOW::LogData("Client -> Server:", data);

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
                UI_WINDOW::LogData("Server -> Client:", data);

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

    void printActiveThreads() {
        std::lock_guard<std::mutex> lock(threadMapMutex);
        UI_WINDOW::UpdateRunningHosts(threadMap); // Gửi thông tin lên giao diện
    }

    // Function to check active threads and stop the ones with a Blacklisted HOST
    void checkAndStopBlacklistedThreads() {
        std::lock_guard<std::mutex> lock(threadMapMutex); 
        for (auto& [id, hostPair] : threadMap) {
            const std::string& host = hostPair.first;
            if (UI_WINDOW::listType == 0) {
                if (Blacklist::isBlocked(host)) {
                    stopFlags[id] = true;  // Set flag to true to stop the thread
                }
            } else {
                if (!Whitelist::isAble(host)) {
                    stopFlags[id] = true;
                }
            }
        }
    }

    void handleClient(SOCKET clientSocket) {
        // Nhận yêu cầu CONNECT từ client
        char buffer[BUFFER_SIZE];
        int receivedBytes = recv(clientSocket, buffer, BUFFER_SIZE, 0);
        if (receivedBytes <= 0) {
            UI_WINDOW::UpdateLog("No data received or connection closed by client.");
            closesocket(clientSocket);
            return;
        }

        std::string request(buffer, receivedBytes);
        // Kiểm tra xem yêu cầu có phải là CONNECT hay không
        if (request.substr(0, 3) == "GET" || request.substr(0, 4) == "POST") {
            std::string host = parseHttpRequest(request);
            int port = 80; // Default HTTP port
            SOCKET remoteSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            
            // Resolve host and connect
            sockaddr_in serverAddr;
            serverAddr.sin_family = AF_INET;
            serverAddr.sin_port = htons(port);
            struct hostent* remoteHost = gethostbyname(host.c_str());
            if (remoteHost == NULL) {
                UI_WINDOW::UpdateLog("Cannot resolve hostname.");
                closesocket(remoteSocket);
                closesocket(clientSocket);
                return;
            }
            memcpy(&serverAddr.sin_addr.s_addr, remoteHost->h_addr, remoteHost->h_length);
            if (connect(remoteSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
                UI_WINDOW::UpdateLog("Cannot connect to remote server.");
                closesocket(remoteSocket);
                closesocket(clientSocket);
                return;
            }

            // Forward the request
            send(remoteSocket, request.c_str(), request.size(), 0);

            // Relay the response back to the client
            char buffer[BUFFER_SIZE];
            int bytesRead;
            while ((bytesRead = recv(remoteSocket, buffer, BUFFER_SIZE, 0)) > 0) {
                send(clientSocket, buffer, bytesRead, 0);
            }

            closesocket(remoteSocket);
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

        // Phản hồi cho client rằng kết nối đã được thiết lập
        const char* connectionEstablished = 
            "HTTP/1.1 200 Connection Established\r\n"
            "Proxy-Agent: CustomProxy/1.0\r\n"
            "\r\n";

        send(clientSocket, connectionEstablished, strlen(connectionEstablished), 0);

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

        UI_WINDOW::UpdateLog("Connecting: " + host + ":" + std::to_string(port));
        handleSSLConnection(clientSocket, host, port, global_ssl_ctx);

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

namespace TransparentNetworkHandle {
    // Biến toàn cục
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
        
        return "https://" + request.substr(start, end - start);
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

    void printActiveThreads() {
        // std::lock_guard<std::mutex> lock(threadMapMutex);
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

    void handleClient(SOCKET clientSocket) {
        char buffer[BUFFER_SIZE];
        int receivedBytes = recv(clientSocket, buffer, BUFFER_SIZE, 0);
        if (receivedBytes <= 0) {
            return;
        }

        std::string request(buffer, receivedBytes);
        std::string url = parseHttpRequest(request);
        if (url.empty()) {
            return;
        }

        size_t hostPos = request.find(' ') + 1;
        if (std::string(url.begin() + 7, url.end()).find(':') == std::string::npos) {
            closesocket(clientSocket);
            return;
        }

        size_t portPos = request.find(':', hostPos);
        std::string host = request.substr(hostPos, portPos - hostPos);
        int port = stoi(request.substr(portPos + 1, request.find(' ', portPos) - portPos - 1));

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
        
        UI_WINDOW::UpdateLog("Connecting: " + host);
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
