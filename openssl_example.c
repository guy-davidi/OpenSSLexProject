#include "openssl_example.h"

int main() {
    RSA *rsa = RSA_new();

    // Generate RSA key pair
    BIGNUM *e = BN_new();
    BN_set_word(e, RSA_F4);
    RSA_generate_key_ex(rsa, RSA_KEY_LENGTH, e, NULL);

    // Get the public and private keys
    EVP_PKEY *private_key = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(private_key, rsa);
    EVP_PKEY *public_key = EVP_PKEY_new();
    EVP_PKEY_assign(public_key, EVP_PKEY_RSA, rsa);

    // Write the private key to a file
    FILE *private_key_file = fopen("private_key.pem", "wb");
    PEM_write_PrivateKey(private_key_file, private_key, NULL, NULL, 0, NULL, NULL);
    fclose(private_key_file);

    // Write the public key to a file
    FILE *public_key_file = fopen("public_key.pem", "wb");
    PEM_write_PUBKEY(public_key_file, public_key);
    fclose(public_key_file);

    // Encrypt and decrypt a message using the keys
    const char *message = "Hello, World!";
    size_t encrypted_length;
    unsigned char encrypted[RSA_KEY_LENGTH / 8];
    unsigned char decrypted[RSA_KEY_LENGTH / 8];

    // Encrypt the message using the public key
    public_key_file = fopen("public_key.pem", "rb");
    public_key = PEM_read_PUBKEY(public_key_file, NULL, NULL, NULL);
    encrypted_length = RSA_public_encrypt(strlen(message) + 1, (unsigned char *)message,
                                          encrypted, EVP_PKEY_get0_RSA(public_key), RSA_PKCS1_PADDING);
    fclose(public_key_file);

    // Decrypt the message using the private key
    private_key_file = fopen("private_key.pem", "rb");
    private_key = PEM_read_PrivateKey(private_key_file, NULL, NULL, NULL);
    RSA_private_decrypt(encrypted_length, encrypted, decrypted,
                                           EVP_PKEY_get0_RSA(private_key), RSA_PKCS1_PADDING);
    fclose(private_key_file);

    // Print the decrypted message
    printf("Decrypted Message: %s\n", decrypted);

    // Free the memory
    RSA_free(rsa);
    BN_free(e);
    EVP_PKEY_free(private_key);
    EVP_PKEY_free(public_key);

    return 0;
}
