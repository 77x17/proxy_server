#ifndef MITM_NETWORK_HANDLE_H
#define MITM_NETWORK_HANDLE_H

#include <winsock2.h>
#include <windows.h>
#include <iostream>
#include <string>
#include <thread>
#include <atomic>
#include <mutex>
#include <map>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/bn.h>
#include <openssl/x509v3.h>
#include <ws2tcpip.h>

#include "ui.h"
#include "constants.h"
#include "blacklist.h"
#include "whitelist.h"

extern EVP_PKEY* caKey;
extern X509* caCert;

namespace MITMNetworkHandle {
    extern std::map<std::string, std::string> hostRequestMap;
    extern SSL_CTX* global_ssl_ctx;

    std::string parseHttpRequest(const std::string &request);
    void        printActiveThreads();
    void        checkAndStopBlacklistedThreads();
    void        initializeOpenSSL();
    void        cleanupOpenSSL();
    EVP_PKEY*   generateRSAKey();
    X509*       generateSelfSignedCert(EVP_PKEY* pkey, const std::string& host);
    bool        writeCertToFile(X509* cert, const std::string& filename);
    SSL_CTX*    createFakeSSLContext(EVP_PKEY* pkey, X509* cert);
    void        handleSSLConnection(SOCKET clientSocket, const std::string& host, int port, SSL_CTX* ctx, const std::string& clientIP);
    void        handleHttpRequest(SOCKET clientSocket, const std::string& host, int port, const std::string& request, const std::string& clientIP);
    void        handleClient(SOCKET clientSocket);
}

#endif 