using System;
using System.Security.Cryptography;
using System.Text;

namespace PassphraseStringCrypto;

internal static class StringEncryptionUtils
{
    const int __iterations = 2_000_000;

    public static string Encrypt(string stringToEncrypt, string passphrase)
    {
        byte[] salt = new byte[8];
        CryptoRandom.WriteCryptoRandomBytes(salt);

        var deriveBytes = new Rfc2898DeriveBytes(passphrase, salt, __iterations);
        byte[] key = deriveBytes.GetBytes(32);

        byte[] plaintext = Encoding.UTF8.GetBytes(stringToEncrypt);
        byte[] ciphertext = AesGsmCrypto.Encrypt(plaintext, key);

        // Prepend the key derivation salt onto the ciphertext.
        byte[] saltAndCiphertext = new byte[salt.Length + ciphertext.Length];
        Array.Copy(salt, 0, saltAndCiphertext, 0, salt.Length);
        Array.Copy(ciphertext, 0, saltAndCiphertext, salt.Length, ciphertext.Length);

        return Base64Utils.ToAlternativeBase64(saltAndCiphertext);
    }

    public static string Decrypt(string abase64ToDecrypt, string passphrase)
    {
        // Decode the hex string to bytes.
        byte[] saltAndCipertext = Base64Utils.FromAlternativeBase64(abase64ToDecrypt);

        // Split the bytes into the key derivation salt, and the ciphertext.
        byte[] salt = new byte[8];
        byte[] ciphertext = new byte[saltAndCipertext.Length - 8];
        Array.Copy(saltAndCipertext, 0, salt, 0, salt.Length);
        Array.Copy(saltAndCipertext, salt.Length, ciphertext, 0, ciphertext.Length);

        // Re-derive the key used at encryption time, using the passphrase and the key derivation salt.
        var deriveBytes = new Rfc2898DeriveBytes(passphrase, salt, __iterations);
        byte[] key = deriveBytes.GetBytes(32);

        // Decrypt the ciphertext to plaintext bytes.
        byte[] plaintext = AesGsmCrypto.Decrypt(ciphertext, key);

        // Decode the UTF8 bytes to a string.
        string decryptedString = Encoding.UTF8.GetString(plaintext);

        return decryptedString;
    }
}
