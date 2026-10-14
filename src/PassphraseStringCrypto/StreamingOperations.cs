using System;
using System.IO;

namespace PassphraseStringCrypto;

internal static class StreamingOperations
{
    public static int Encrypt(
        TextReader input,
        TextWriter output,
        TextWriter error,
        Func<string, string> readPassphrase,
        bool inputRedirected,
        bool outputRedirected)
    {
        if(!RequireRedirection(error, inputRedirected, outputRedirected))
            return 2;

        string plaintext = input.ReadLine();
        if(plaintext is null || input.ReadToEnd().Length != 0)
        {
            error.WriteLine("Error: encrypt-stdin requires exactly one input line.");
            return 2;
        }

        string passphrase = readPassphrase("Encryption passphrase: ");
        string repeatedPassphrase = readPassphrase("Repeat encryption passphrase: ");
        if(passphrase.Length == 0 || !string.Equals(passphrase, repeatedPassphrase, StringComparison.Ordinal))
        {
            error.WriteLine("Error: passphrases are empty or do not match.");
            return 2;
        }

        output.WriteLine(StringEncryptionUtils.Encrypt(plaintext, passphrase));
        output.Flush();
        return 0;
    }

    public static int Decrypt(
        TextReader input,
        TextWriter output,
        TextWriter error,
        Func<string, string> readPassphrase,
        bool inputRedirected,
        bool outputRedirected)
    {
        if(!RequireRedirection(error, inputRedirected, outputRedirected))
            return 2;

        string ciphertext = RemoveWhitespace(input.ReadToEnd());
        if(ciphertext.Length == 0)
        {
            error.WriteLine("Error: decrypt-stdin received no ciphertext.");
            return 2;
        }

        string passphrase = readPassphrase("Decryption passphrase: ");
        if(passphrase.Length == 0)
        {
            error.WriteLine("Error: passphrase is empty.");
            return 2;
        }

        output.WriteLine(StringEncryptionUtils.Decrypt(ciphertext, passphrase));
        output.Flush();
        return 0;
    }

    private static bool RequireRedirection(
        TextWriter error,
        bool inputRedirected,
        bool outputRedirected)
    {
        if(!inputRedirected || !outputRedirected)
        {
            error.WriteLine(
                "Error: secure modes require both standard input and standard output to be redirected.");
            return false;
        }

        return true;
    }

    private static string RemoveWhitespace(string value)
    {
        char[] compacted = new char[value.Length];
        int writeIndex = 0;
        foreach(char ch in value)
        {
            if(!char.IsWhiteSpace(ch))
                compacted[writeIndex++] = ch;
        }

        return new string(compacted, 0, writeIndex);
    }
}
