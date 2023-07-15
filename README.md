## Server-Client Application with OpenSSL (Multi-Threaded)
This is a simple server-client application that demonstrates secure communication using OpenSSL and utilizes a multi-threaded system with the select mechanism. The server and client communicate over a secure SSL/TLS connection.

Features
- Secure communication between the server and client using OpenSSL.
- Multi-threaded architecture with the select mechanism for handling multiple client connections concurrently.
- Server supports multiple client connections simultaneously.
- Server echoes the received messages back to the client.
- Prerequisites
- OpenSSL library must be installed on the system.
- C compiler (e.g., GCC) with pthread and OpenSSL development libraries.

# Getting Started
Clone the repository:

```
git clone https://github.com/your-username/server-client-openssl-select.git
```
Compile the server and client applications:
```
cd server-client-openssl-select
make all
```
Generate SSL certificate and private key:
Generate a self-signed SSL certificate and private key using OpenSSL. Run the following commands in the terminal:
```
openssl req -x509 -newkey rsa:4096 -nodes -keyout server.key -out server.crt -days 365
```
Follow the prompts to enter the required details for the certificate.

Start the server:
```
./server
```
Start the client:
```
./client
```
Follow the instructions displayed by the client application to send messages to the server and receive echoed responses.
The server application listens for incoming client connections on a specified port (default port: 8888).
The client application connects to the server using the server's IP address and port number.
Once connected, the client can send messages to the server, which will be echoed back to the client.
Multiple clients can connect to the server simultaneously and communicate independently.

# Contributing
Contributions are welcome! If you find any issues or have suggestions for improvement, please submit an issue or pull request.

# License
MIT License
