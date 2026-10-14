using System;
using System.Linq;
using System.Security.Cryptography;

namespace PassphraseStringCrypto;

internal static class AesGsmCrypto
{
    public const int HeaderLength = 30;
    private const int __tagLength = 16;
    private static readonly int[] __keySizes = new int[] { 16, 24, 32 };

    public static byte[] Encrypt(Span<byte> plaintext, Span<byte> key)
    {
        // Check that the provided key has one of the allowed/supported key lengths.
        if(!__keySizes.Contains(key.Length)) {
            throw new CryptographicException("Unsupported key size.");
        }

        if(plaintext.Length > ushort.MaxValue){
            throw new CryptographicException("Plaintext too long for this crypto scheme.");
        }

        // Create an empty byte array that we will write into to create the crypto bytes to return from this method.
        // The final output we create will have the following structure:
        //    nonce (12 bytes)
        //    dataLen (2 bytes)
        //    authTag (16 bytes)
        //    ciphertext (variable length, and described by the dataLen field)
        int dataLen = plaintext.Length;
        byte[] ciphertext = new byte[HeaderLength + dataLen];

        // Create spans over the various fields/segments within the ciphertext array.
        // Nonce span
        int writeIdx = 0;
        int nonceSpanIdx = writeIdx;
        Span<byte> nonceSpan = ciphertext.AsSpan(writeIdx, 12);
        writeIdx += 12;

        // Data length span.
        Span<byte> dataLenSpan = ciphertext.AsSpan(writeIdx, 2);
        writeIdx += 2;

        // Authentication tag span.
        Span<byte> authTagSpan = ciphertext.AsSpan(writeIdx, __tagLength);
        writeIdx += __tagLength;

        // Ciphertext span.
        Span<byte> ciphertextSpan = ciphertext.AsSpan(writeIdx, dataLen);

        // Now we enter the AesGcm scheme specific bytes/encoding.
        // Generate 12 random nonce bytes.
        CryptoRandom.WriteCryptoRandomBytes(nonceSpan);

        // Write the data length. For AES-GCM the ciphertext length is always equal to the plaintext length,
        // therefore we are able to write this before we have produced the ciphertext.
        BinaryUtils.WriteUInt16((ushort)dataLen, dataLenSpan);

        // Initialise an instance of AesCgm, and encrypt the plaintext, writing ciphertext bytes into ciphertextSpan.
        // This will also consume dataLenSpan (as associated data), and write bytes into authTagSpan.
        using AesGcm aesGcm = new AesGcm(key, __tagLength);
        aesGcm.Encrypt(nonceSpan, plaintext, ciphertextSpan, authTagSpan, dataLenSpan);

        // Return ciphertext; this is our completed block of scheme specific ciphertext.
        return ciphertext;
    }

    public static byte[] Decrypt(Span<byte> ciphertext, Span<byte> key)
    {
        // Check that the provided key has one of the allowed/supported key lengths.
        if(!__keySizes.Contains(key.Length)) {
            throw new CryptographicException("Unsupported key size.");
        }

        if(ciphertext.Length < HeaderLength || ciphertext.Length > ushort.MaxValue){
            throw new CryptographicException("Ciphertext too long for this crypto scheme.");
        }

        // Create spans over the various fields/segments within the ciphertext span.
        int readIdx = 0;
        Span<byte> nonceSpan = ciphertext.Slice(readIdx, 12);
        readIdx += 12;

        // Data length span.
        Span<byte> dataLenSpan = ciphertext.Slice(readIdx, 2);
        readIdx += 2;

        // Authentication tag span.
        Span<byte> authTagSpan = ciphertext.Slice(readIdx, __tagLength);
        readIdx += __tagLength;

        // Read the data length.
        int dataLen = BinaryUtils.ReadUInt16(dataLenSpan);
        int dataLenActual = ciphertext.Length - HeaderLength;
        if(dataLen != dataLenActual) {
            throw new CryptographicException("Ciphertext data length field does not match length of the encrypted.");
        }

        // Ciphertext span.
        Span<byte> ciphertextSpan = ciphertext.Slice(readIdx, dataLen);

        // Initialise an instance of AesCgm, and decrypt the ciphertext, writing plaintext bytes into a new array.
        // This will also consume authTagSpan and associatedDataSpan, and Decrypt() will fail if the associated data has been tampered with in any way.
        byte[] plaintext = new byte[dataLen];
        using AesGcm aesGcm = new AesGcm(key, __tagLength);
        aesGcm.Decrypt(nonceSpan, ciphertextSpan, authTagSpan, plaintext, dataLenSpan);

        // Return the decrypted plaintext.
        return plaintext;
    }

}
