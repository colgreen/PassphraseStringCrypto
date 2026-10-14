using System;
using System.Security.Cryptography;
using System.Text;

namespace PassphraseStringCrypto;

internal static class StringEncryptionUtils
{
    const int __iterations = 2_000_000;
    const int __saltLength = 8;
    const int __keyLength = 32;

    public static string Encrypt(string stringToEncrypt, string passphrase)
    {
        byte[] salt = new byte[__saltLength];
        CryptoRandom.WriteCryptoRandomBytes(salt);

        byte[] plaintext = Encoding.UTF8.GetBytes(stringToEncrypt);
        byte[] key = Rfc2898DeriveBytes.Pbkdf2(
            passphrase,
            salt,
            __iterations,
            HashAlgorithmName.SHA1,
            __keyLength);

        try
        {
            byte[] ciphertext = AesGsmCrypto.Encrypt(plaintext, key);

            // Prepend the key derivation salt onto the ciphertext.
            byte[] saltAndCiphertext = new byte[salt.Length + ciphertext.Length];
            Array.Copy(salt, 0, saltAndCiphertext, 0, salt.Length);
            Array.Copy(ciphertext, 0, saltAndCiphertext, salt.Length, ciphertext.Length);

            return Base64Utils.ToAlternativeBase64(saltAndCiphertext);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    public static string Decrypt(string abase64ToDecrypt, string passphrase)
    {
        // Decode the hex string to bytes.
        byte[] saltAndCipertext = Base64Utils.FromAlternativeBase64(abase64ToDecrypt);
        if(saltAndCipertext.Length < __saltLength + AesGsmCrypto.HeaderLength)
            throw new CryptographicException("Ciphertext is too short.");

        // Split the bytes into the key derivation salt, and the ciphertext.
        byte[] salt = new byte[__saltLength];
        byte[] ciphertext = new byte[saltAndCipertext.Length - __saltLength];
        Array.Copy(saltAndCipertext, 0, salt, 0, salt.Length);
        Array.Copy(saltAndCipertext, salt.Length, ciphertext, 0, ciphertext.Length);

        // Re-derive the key used at encryption time, using the passphrase and the key derivation salt.
        byte[] key = Rfc2898DeriveBytes.Pbkdf2(
            passphrase,
            salt,
            __iterations,
            HashAlgorithmName.SHA1,
            __keyLength);

        byte[] plaintext = Array.Empty<byte>();
        try
        {
            // Decrypt the ciphertext to plaintext bytes.
            plaintext = AesGsmCrypto.Decrypt(ciphertext, key);

            // Decode the UTF8 bytes to a string.
            return Encoding.UTF8.GetString(plaintext);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }
}
