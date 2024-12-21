#include "ui.h"
#include "network_init.h"

namespace NetworkInit {
    // Cấu trúc (structure) chứa thông tin về việc khởi tạo Winsock trong môi trường Winsock API.
    void initWinsock() {
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            UI_WINDOW::UpdateLog("WSAStartup failed.", std::string());
            
            exit(EXIT_FAILURE);
        }
    }

    // socket(): Đây là hàm được sử dụng để tạo ra một socket. Socket là một điểm cuối trong giao tiếp mạng. 
    //           Các tham số của hàm này bao gồm:
    //                 AF_INET    : Đây là family của địa chỉ, chỉ định sử dụng giao thức IPv4.
    //                 SOCK_STREAM: Xác định loại socket, trong trường hợp này là một socket dòng (stream), 
    //                              nghĩa là một kết nối TCP, nơi dữ liệu được truyền tải dưới dạng dòng liên tục.
    //                 IPPROTO_TCP: Chỉ định giao thức sẽ được sử dụng, ở đây là giao thức TCP.
    SOCKET createSocket() {
        SOCKET listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (listenSocket == INVALID_SOCKET) {
            UI_WINDOW::UpdateLog("Socket creation failed.", std::string());
            
            WSACleanup();
            exit(EXIT_FAILURE);
        }

        return listenSocket;
    }

    void bindSocket(SOCKET listenSocket) {
        sockaddr_in serverAddr;                  // Định nghĩa địa chỉ của server
        serverAddr.sin_family = AF_INET;         // Định dạng địa chỉ IPv4
        serverAddr.sin_addr.s_addr = INADDR_ANY; // Chấp nhận kết nối từ mọi địa chỉ IP
        serverAddr.sin_port = htons(PORT);       // Chuyển cổng sang định dạng network byte order

        if (bind(listenSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
            UI_WINDOW::UpdateLog("Bind failed.", std::string());
            closesocket(listenSocket);
            WSACleanup();
            exit(EXIT_FAILURE);
        }
    }

    void startListening(SOCKET listenSocket) {
        if (listen(listenSocket, SOMAXCONN) == SOCKET_ERROR) {
            UI_WINDOW::UpdateLog("Listen failed.", std::string());
            closesocket(listenSocket);
            WSACleanup();
            exit(EXIT_FAILURE);
        }

        UI_WINDOW::UpdateLog("Proxy server started. Listening on port " + std::to_string(PORT) + "...", std::string());
    }

    SOCKET startInitSocket() {
        initWinsock();
        SOCKET listenSocket = createSocket();
        bindSocket(listenSocket);
        startListening(listenSocket);
        
        return listenSocket;
    }
}

