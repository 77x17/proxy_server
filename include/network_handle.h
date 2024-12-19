#ifndef NETWORK_HANDLE_H
#define NETWORK_HANDLE_H

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

#include "ui.h"
#include "constants.h"
#include "blacklist.h"
#include "whitelist.h"

namespace MITMNetworkHandle {
    extern std::map<std::string, std::string> hostRequestMap;
    extern SSL_CTX* global_ssl_ctx;

    std::string parseHttpRequest(const std::string &request);
    void        handleConnectMethod(SOCKET clientSocket, const std::string& host, int port);
    void        initializeOpenSSL();
    void        cleanupOpenSSL();
    EVP_PKEY*   generateRSAKey();
    X509*       generateSelfSignedCert(EVP_PKEY* pkey, const std::string& host);
    bool        writeCertToFile(X509* cert, const std::string& filename);
    SSL_CTX*    createFakeSSLContext(EVP_PKEY* pkey, X509* cert);
    void        printActiveThreads();
    void        handleClient(SOCKET clientSocket);
    void        checkAndStopBlacklistedThreads();
}

namespace TransparentNetworkHandle {
    extern std::map<std::string, std::string> hostRequestMap;
    
    std::string parseHttpRequest(const std::string &request);
    void        handleConnectMethod(SOCKET clientSocket, const std::string& host, int port);
    void        printActiveThreads();
    void        handleClient(SOCKET clientSocket);
    void        checkAndStopBlacklistedThreads();
}

#endif 