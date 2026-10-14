using PassphraseStringCrypto;

namespace PassphraseStringCryptoTests;

public class StreamingOperationsTests
{
    [Fact]
    public void SecureModesRoundtripWithoutWritingSecretsToDiagnostics()
    {
        const string plaintext = "unmistakably-fake-test-root";
        const string passphrase = "unmistakably-fake-test-passphrase";
        var encryptionPrompts = new Queue<string>(new[] { passphrase, passphrase });
        using var ciphertextOutput = new StringWriter();
        using var encryptionError = new StringWriter();

        int encryptResult = StreamingOperations.Encrypt(
            new StringReader(plaintext + Environment.NewLine),
            ciphertextOutput,
            encryptionError,
            _ => encryptionPrompts.Dequeue(),
            inputRedirected: true,
            outputRedirected: true);

        Assert.Equal(0, encryptResult);
        Assert.DoesNotContain(plaintext, encryptionError.ToString());
        Assert.DoesNotContain(passphrase, encryptionError.ToString());

        using var plaintextOutput = new StringWriter();
        using var decryptionError = new StringWriter();
        int decryptResult = StreamingOperations.Decrypt(
            new StringReader(ciphertextOutput.ToString()),
            plaintextOutput,
            decryptionError,
            _ => passphrase,
            inputRedirected: true,
            outputRedirected: true);

        Assert.Equal(0, decryptResult);
        Assert.Equal(plaintext + Environment.NewLine, plaintextOutput.ToString());
        Assert.DoesNotContain(plaintext, decryptionError.ToString());
        Assert.DoesNotContain(passphrase, decryptionError.ToString());
    }

    [Fact]
    public void SecureModeRequiresRedirectedInputAndOutput()
    {
        using var output = new StringWriter();
        using var error = new StringWriter();

        int result = StreamingOperations.Encrypt(
            new StringReader("fake"),
            output,
            error,
            _ => throw new InvalidOperationException("Prompt must not be reached."),
            inputRedirected: false,
            outputRedirected: true);

        Assert.Equal(2, result);
        Assert.Empty(output.ToString());
        Assert.Contains("require both", error.ToString());
    }

    [Fact]
    public void EncryptRejectsMismatchedPassphrasesWithoutOutput()
    {
        var passphrases = new Queue<string>(new[] { "fake-one", "fake-two" });
        using var output = new StringWriter();
        using var error = new StringWriter();

        int result = StreamingOperations.Encrypt(
            new StringReader("fake"),
            output,
            error,
            _ => passphrases.Dequeue(),
            inputRedirected: true,
            outputRedirected: true);

        Assert.Equal(2, result);
        Assert.Empty(output.ToString());
        Assert.Contains("do not match", error.ToString());
    }
}
