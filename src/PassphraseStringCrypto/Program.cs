using System;
using System.Text;
using static PassphraseStringCrypto.StringEncryptionUtils;

namespace PassphraseStringCrypto;

public class Program
{
    static void Main(string[] args)
    {
        bool success = ArgUtils.ReadArgs(
            args,
            out bool encrypt, 
            out string text,
            out string passphrase);

        if(!success) 
            return;

        if(encrypt)
        {
            string ciphertextAltBase64 = Encrypt(text, passphrase);
            DumpToConsole(ciphertextAltBase64);
        }
        else
        {
            string decryptedString = Decrypt(text, passphrase);
            Console.WriteLine(decryptedString);
        }
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
