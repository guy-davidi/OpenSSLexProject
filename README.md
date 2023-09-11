# OpenSSL

This project provides a basic example of using the OpenSSL library in a C/C++ program.
It demonstrates how to generate an RSA key pair, perform encryption and decryption using the keys, and save the keys to PEM files.

## Getting Started

1. Clone the repository or download the source code files.

git clone https://github.com/guy-davidi/OpenSSLexProject.git

2. Compile the source code using the following command:

gcc openssl_example.c -o example -lssl -lcrypto

Make sure to replace `openssl_example.c` with the actual filename if necessary.

## Usage

1. Run the compiled program:

./example

2. The program will generate an RSA key pair and save the private key and public key to separate PEM files (`private_key.pem` and `public_key.pem`).

3. The program will encrypt and decrypt a sample message using the generated keys, demonstrating the encryption and decryption process.

4. The decrypted message will be displayed on the console.

## Customization

- You can modify the `RSA_KEY_LENGTH` constant in the source code to change the key length (in bits) for the generated RSA key pair. The default value is 2048 bits.

- Feel free to modify the sample message in the source code to encrypt and decrypt your own messages.

## Contributing

Contributions to this project are welcome. If you encounter any issues or have suggestions for improvements, please submit an issue or a pull request.

## License

This project is licensed under the [MIT License](LICENSE).

## Acknowledgements

This project is inspired by the OpenSSL library and its  community of contributors.
