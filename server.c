// server.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define MAX_CLIENTS 10
#define BUFFER_SIZE 1024

int main(int argc, char *argv[]) {
    int serverSocket, clientSockets[MAX_CLIENTS], maxSd, activity, i, valread, sd;
    int maxClients = MAX_CLIENTS;
    struct sockaddr_in address;
    char buffer[BUFFER_SIZE];
    SSL_CTX *sslContext;
    SSL *ssl;

    // Create SSL context
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    sslContext = SSL_CTX_new(SSLv23_server_method());

    // Load SSL certificate and key
    if (SSL_CTX_use_certificate_file(sslContext, "server.crt", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(sslContext, "server.key", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (!SSL_CTX_check_private_key(sslContext)) {
        fprintf(stderr, "Private key does not match the certificate public key\n");
        exit(EXIT_FAILURE);
    }

    // Create server socket
    if ((serverSocket = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    // Set socket options
    if (setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) < 0) {
        perror("setsockopt failed");
        exit(EXIT_FAILURE);
    }

    // Set server address
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(8888);

    // Bind server socket
    if (bind(serverSocket, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    // Listen for connections
    if (listen(serverSocket, 5) < 0) {
        perror("listen failed");
        exit(EXIT_FAILURE);
    }

    // Initialize client sockets array
    for (i = 0; i < maxClients; i++) {
        clientSockets[i] = 0;
    }

    while (1) {
        fd_set readFds;

        // Clear the socket set
        FD_ZERO(&readFds);

        // Add server socket to the set
        FD_SET(serverSocket, &readFds);
        maxSd = serverSocket;

        // Add client sockets to the set
        for (i = 0; i < maxClients; i++) {
            sd = clientSockets[i];

            if (sd > 0) {
                FD_SET(sd, &readFds);
            }

            if (sd > maxSd) {
                maxSd = sd;
            }
        }

        // Wait for activity on any socket
        activity = select(maxSd + 1, &readFds, NULL, NULL, NULL);
        if ((activity < 0) && (errno != EINTR)) {
            perror("select error");
        }

        // Check if server socket has activity
        if (FD_ISSET(serverSocket, &readFds)) {
            int newSocket;
            struct sockaddr_in clientAddress;
            socklen_t clientAddressLength = sizeof(clientAddress);

            // Accept new connection
            if ((newSocket = accept(serverSocket, (struct sockaddr *)&clientAddress, &clientAddressLength)) < 0) {
                perror("accept failed");
                exit(EXIT_FAILURE);
            }

            // Create SSL connection
            ssl = SSL_new(sslContext);
            SSL_set_fd(ssl, newSocket);
            if (SSL_accept(ssl) <= 0) {
                ERR_print_errors_fp(stderr);
                exit(EXIT_FAILURE);
            }

            // Print client IP and port
            char clientIp[INET_ADDRSTRLEN];
            printf("New connection, IP: %s, Port: %d\n",
                   inet_ntop(AF_INET, &(clientAddress.sin_addr), clientIp, INET_ADDRSTRLEN),
                   ntohs(clientAddress.sin_port));

            // Add new socket to client sockets array
            for (i = 0; i < maxClients; i++) {
                if (clientSockets[i] == 0) {
                    clientSockets[i] = newSocket;
                    break;
                }
            }
        }

        // Check for I/O activity on client sockets
        for (i = 0; i < maxClients; i++) {
            sd = clientSockets[i];

            if (FD_ISSET(sd, &readFds)) {
                // Receive data from client
                if ((valread = SSL_read(ssl, buffer, BUFFER_SIZE)) <= 0) {
                    // Connection closed or error occurred
                    struct sockaddr_in address;
                    socklen_t addressLength = sizeof(address);
                    char clientIp[INET_ADDRSTRLEN];

                    getpeername(sd, (struct sockaddr *)&address, (socklen_t *)&addressLength);
                    printf("Client disconnected, IP: %s, Port: %d\n",
                           inet_ntop(AF_INET, &(address.sin_addr), clientIp, INET_ADDRSTRLEN),
                           ntohs(address.sin_port));

                    // Close the socket and remove from client sockets array
                    close(sd);
                    clientSockets[i] = 0;
                } else {
                    // Echo received data back to client
                    SSL_write(ssl, buffer, valread);
                }
            }
        }
    }

    // Clean up
    SSL_free(ssl);
    SSL_CTX_free(sslContext);
    close(serverSocket);

    return 0;
}
