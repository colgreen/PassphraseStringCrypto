using System;
using System.ComponentModel;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using static PassphraseStringCrypto.StringEncryptionUtils;

namespace PassphraseStringCrypto;

public class Program
{
    static int Main(string[] args)
    {
        try
        {
            if(args.Length == 1 && args[0].Equals("encrypt-stdin", StringComparison.OrdinalIgnoreCase))
            {
                return StreamingOperations.Encrypt(
                    Console.In,
                    Console.Out,
                    Console.Error,
                    TerminalPassphraseReader.Read,
                    Console.IsInputRedirected,
                    Console.IsOutputRedirected);
            }

            if(args.Length == 1 && args[0].Equals("decrypt-stdin", StringComparison.OrdinalIgnoreCase))
            {
                return StreamingOperations.Decrypt(
                    Console.In,
                    Console.Out,
                    Console.Error,
                    TerminalPassphraseReader.Read,
                    Console.IsInputRedirected,
                    Console.IsOutputRedirected);
            }

            return RunLegacyCommand(args);
        }
        catch(Exception ex) when(ex is CryptographicException
            or FormatException
            or IOException
            or InvalidOperationException
            or NotSupportedException
            or Win32Exception)
        {
            Console.Error.WriteLine("Error: encryption operation failed.");
            return 1;
        }
    }

    private static int RunLegacyCommand(string[] args)
    {
        bool success = ArgUtils.ReadArgs(
            args,
            out bool encrypt, 
            out string text,
            out string passphrase);

        if(!success) 
            return 2;

        Console.Error.WriteLine(
            "Warning: legacy mode exposes plaintext/ciphertext and the passphrase in process arguments. "
            + "Use encrypt-stdin or decrypt-stdin for secret material.");

        if(encrypt)
        {
            string ciphertextAltBase64 = Encrypt(text, passphrase);
            DumpToConsole(ciphertextAltBase64);
        }
        else
        {
            string plaintext = Decrypt(text, passphrase);
            Console.WriteLine(plaintext);
        }

        return 0;
    }

    private static void DumpToConsole(string ciphertextAltBase64)
    {
        Console.WriteLine(FormatStringInChunks(ciphertextAltBase64));
        Console.WriteLine();
        Console.WriteLine(ciphertextAltBase64);
    }

    private static string FormatStringInChunks(string input)
    {
        if(string.IsNullOrEmpty(input))
            return input;

        var sb = new StringBuilder();
        for(int i=0; i < input.Length; i++)
        {
            if(i > 0 && i % 8 == 0)
                sb.Append(' ');

            sb.Append(input[i]);
        }

        return sb.ToString();
    }
}
