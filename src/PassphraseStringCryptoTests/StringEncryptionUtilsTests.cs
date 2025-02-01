using PassphraseStringCrypto;

namespace PassphraseStringCryptoTests;

public class StringEncryptionUtilsTests
{
    [Fact]
    public void DecryptTest()
    {
        string ciphertextAltBase64 = "VUuW8IKdZkIf4dXHKQ^EadXjuZ4AEkqeg2CYRac#h5TKDZDxcSWE6Mjek2swf6Ra8^DxhgY~qck=";
        string cleartextActual = StringEncryptionUtils.Decrypt(ciphertextAltBase64, "password 123");
        Assert.Equal("message to encrypt", cleartextActual);
    }

    [Fact]
    public void EncryptDecryptRoundtrip()
    {
        string cleartext = "0123456789012345678901234567890123456789012345678901";
        string passphrase = "correct horse battery staple";
        string ciphertextAltBase64 = StringEncryptionUtils.Encrypt(cleartext, passphrase);
        string cleartextActual = StringEncryptionUtils.Decrypt(ciphertextAltBase64, passphrase);
        Assert.Equal(cleartext, cleartextActual);
    }
}
