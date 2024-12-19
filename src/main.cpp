#include "ui.h"

int main() {
    Blacklist::load(BLACKLIST_URL);
    Whitelist::load(WHITELIST_URL);

    MITMNetworkHandle::initializeOpenSSL();

    // Tạo khóa RSA và chứng chỉ tự ký một lần duy nhất
    std::string host = "myproxy.local"; // Thay đổi theo nhu cầu, nên dùng một tên host phù hợp
    EVP_PKEY* pkey = MITMNetworkHandle::generateRSAKey();
    if (!pkey) {
        std::cerr << "Failed to generate RSA key.\n";
        MITMNetworkHandle::cleanupOpenSSL();
        return -1;
    }

    X509* cert = MITMNetworkHandle::generateSelfSignedCert(pkey, host);
    if (!cert) {
        std::cerr << "Failed to generate self-signed certificate.\n";
        EVP_PKEY_free(pkey);
        MITMNetworkHandle::cleanupOpenSSL();
        return -1;
    }

    // (Tùy chọn) Ghi chứng chỉ ra tệp để cài đặt vào client nếu cần
    if (!MITMNetworkHandle::writeCertToFile(cert, "proxy_ca.crt")) {
        std::cerr << "Failed to write certificate to file.\n";
        X509_free(cert);
        EVP_PKEY_free(pkey);
        MITMNetworkHandle::cleanupOpenSSL();
        return -1;
    }

    // Tạo SSL_CTX cố định cho proxy
    MITMNetworkHandle::global_ssl_ctx = MITMNetworkHandle::createFakeSSLContext(pkey, cert);
    if (!MITMNetworkHandle::global_ssl_ctx) {
        std::cerr << "Failed to create SSL context.\n";
        X509_free(cert);
        EVP_PKEY_free(pkey);
        MITMNetworkHandle::cleanupOpenSSL();
        return -1;
    }

    // Giải phóng chứng chỉ và khóa sau khi đã gắn vào SSL_CTX
    X509_free(cert);
    EVP_PKEY_free(pkey);

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