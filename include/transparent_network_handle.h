#ifndef TRANSPARENT_NETWORK_HANDLE_H
#define TRANSPARENT_NETWORK_HANDLE_H

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

namespace TransparentNetworkHandle {
    extern std::map<std::string, std::string> hostRequestMap;
    
    std::string parseHttpRequest(const std::string &request);
    void        printActiveThreads();
    void        checkAndStopBlacklistedThreads();
    void        handleConnectMethod(SOCKET clientSocket, const std::string& host, int port);
    void        handleHttpRequest(SOCKET clientSocket, const std::string& host, int port, const std::string& request);
    void        handleClient(SOCKET clientSocket);
}

#endif 