// client.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define BUFFER_SIZE 1024

int main(int argc, char *argv[]) {
    int clientSocket;
    struct sockaddr_in serverAddress;
    char *serverIp = "127.0.0.1";
    char buffer[BUFFER_SIZE];
    SSL_CTX *sslContext;
    SSL *ssl;

    // Create SSL context
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    sslContext = SSL_CTX_new(TLS_client_method());

    // Create client socket
    if ((clientSocket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    // Set server address
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(8888);

    if (inet_pton(AF_INET, serverIp, &(serverAddress.sin_addr)) <= 0) {
        perror("inet_pton failed");
        exit(EXIT_FAILURE);
    }

    // Connect to server
    if (connect(clientSocket, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0) {
        perror("connect failed");
        exit(EXIT_FAILURE);
    }

    // Create SSL connection
    ssl = SSL_new(sslContext);
    SSL_set_fd(ssl, clientSocket);
    if (SSL_connect(ssl) != 1) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Send and receive data
    while (1) {
        printf("Enter message: ");
        fgets(buffer, BUFFER_SIZE, stdin);

        // Send data to server
        SSL_write(ssl, buffer, strlen(buffer));

        // Receive response from server
        memset(buffer, 0, BUFFER_SIZE);
        SSL_read(ssl, buffer, BUFFER_SIZE);

        printf("Server response: %s\n", buffer);

        if (strncmp(buffer, "exit", 4) == 0) {
            break;
        }
    }

    // Clean up
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(sslContext);
    close(clientSocket);

    return 0;
}
