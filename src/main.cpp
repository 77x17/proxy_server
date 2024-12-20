#include "ui.h"

bool loadRootCA(const std::string& keyPath, const std::string& certPath) {
    // Load Private Key
    FILE* keyFile = fopen(keyPath.c_str(), "r");
    if (!keyFile) {
        std::cerr << "Failed to open Root CA Key file: " << keyPath << "\n";
        return false;
    }
    caKey = PEM_read_PrivateKey(keyFile, nullptr, nullptr, nullptr);
    fclose(keyFile);

    if (!caKey) {
        std::cerr << "Failed to read private key from: " << keyPath << "\n";
        unsigned long err = ERR_get_error();
        std::cerr << "OpenSSL Error: " << ERR_error_string(err, NULL) << "\n";
        return false;
    }

    // Load Certificate
    FILE* certFile = fopen(certPath.c_str(), "r");
    if (!certFile) {
        std::cerr << "Failed to open Root CA Certificate file: " << certPath << "\n";
        return false;
    }
    caCert = PEM_read_X509(certFile, nullptr, nullptr, nullptr);
    fclose(certFile);

    if (!caCert) {
        std::cerr << "Failed to read certificate from: " << certPath << "\n";
        unsigned long err = ERR_get_error();
        std::cerr << "OpenSSL Error: " << ERR_error_string(err, NULL) << "\n";
        return false;
    }

    // Kiểm tra tính hợp lệ của khóa và chứng chỉ
    if (X509_check_private_key(caCert, caKey) <= 0) {
        std::cerr << "The private key does not match the certificate.\n";
        unsigned long err = ERR_get_error();
        std::cerr << "OpenSSL Error: " << ERR_error_string(err, NULL) << "\n";
        return false;
    }

    return true;
}

int main() {
    Blacklist::load(BLACKLIST_URL);
    Whitelist::load(WHITELIST_URL);

    MITMNetworkHandle::initializeOpenSSL();

    // Tạo khóa RSA và chứng chỉ tự ký một lần duy nhất
    std::string host = "myproxy.local"; // Thay đổi theo nhu cầu, nên dùng một tên host phù hợp

    if (!loadRootCA("rootCA.key", "rootCA.crt")) {
        std::cerr << "Failed to load Root CA.\n";
        return -1;
    }

    // Khởi tạo SSL_CTX
    MITMNetworkHandle::global_ssl_ctx = SSL_CTX_new(TLS_server_method());
    if (!MITMNetworkHandle::global_ssl_ctx) {
        std::cerr << "Failed to create global SSL_CTX.\n";
        return -1;
    }

    // Gắn chứng chỉ vào SSL_CTX
    if (SSL_CTX_use_certificate(MITMNetworkHandle::global_ssl_ctx, caCert) <= 0) {
        std::cerr << "Failed to use certificate in SSL_CTX.\n";
        unsigned long err = ERR_get_error();
        std::cerr << "OpenSSL Error: " << ERR_error_string(err, NULL) << "\n";
        return -1;
    }

    // Gắn khóa riêng vào SSL_CTX
    if (SSL_CTX_use_PrivateKey(MITMNetworkHandle::global_ssl_ctx, caKey) <= 0) {
        std::cerr << "Failed to use private key in SSL_CTX.\n";
        unsigned long err = ERR_get_error();
        std::cerr << "OpenSSL Error: " << ERR_error_string(err, NULL) << "\n";
        return -1;
    }

    // Kiểm tra tính hợp lệ của khóa và chứng chỉ
    if (!SSL_CTX_check_private_key(MITMNetworkHandle::global_ssl_ctx)) {
        std::cerr << "Private key does not match the certificate public key.\n";
        return -1;
    }

    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    const char CLASS_NAME[] = "Proxy Server - fit.hcmus.edu.vn";  // Changed to char
    WNDCLASSA wc = {};  // Changed to WNDCLASSA for ANSI version
    wc.lpfnWndProc = UI_WINDOW::WindowProc;
    wc.hInstance = GetModuleHandle(NULL);
    wc.lpszClassName = CLASS_NAME;
    RegisterClassA(&wc);  // Changed to RegisterClassA

    HWND hwnd = CreateWindowA(
        CLASS_NAME, 
        "Proxy Server - fit.hcmus.edu.vn",  // Changed to char
        WS_OVERLAPPEDWINDOW, // Bao gồm hỗ trợ phóng to, thu nhỏ
        CW_USEDEFAULT, CW_USEDEFAULT, 
        800, 600, 
        NULL, NULL,     
        wc.hInstance, 
        NULL
    );

    UI_WINDOW::Init(hwnd, wc.hInstance);

    ShowWindow(hwnd, SW_SHOWNORMAL);
    UpdateWindow(hwnd);

    MSG msg = {};
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    SSL_CTX_free(MITMNetworkHandle::global_ssl_ctx);
    MITMNetworkHandle::cleanupOpenSSL();

    return 0;
}