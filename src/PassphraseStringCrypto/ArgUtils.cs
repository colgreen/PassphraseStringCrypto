using System;

namespace PassphraseStringCrypto
{
    internal static class ArgUtils
    {
        public static bool ReadArgs(
            string[] args,
            out bool encrypt, 
            out string text,
            out string passphrase)
        {
            encrypt = false;
            text = null;
            passphrase = null;

            if(args.Length != 3)
            {
                PrintHelp();
                return false;
            }

            string op = args[0].ToLowerInvariant();
            switch(op)
            {
                case "encrypt":
                    encrypt = true;
                    break;
                case "decrypt":
                    encrypt = false;
                    break;
                default:
                    PrintHelp();
                    return false;
            }

            text = args[1];
            passphrase = args[2];

            if(!encrypt) {
                text = RemoveWhitespace(text);
            }

            return true;
        }

        private static string RemoveWhitespace(string str)
        {
            char[] arr = str.ToCharArray();
            char[] arr2 = new char[arr.Length];

            int writeIdx = 0;
            for(int i=0; i < arr.Length; i++)
            {
                char ch = arr[i];
                if(!char.IsWhiteSpace(ch))
                {
                    arr2[writeIdx++] = ch;
                }
            }

            return new string(arr2, 0, writeIdx);
        }

        private static void PrintHelp()
        {
            Console.WriteLine("Format is:");
            Console.WriteLine("  scrypto encrypt \"<plaintext>\" \"<passphrase>\"");
            Console.WriteLine("  scrypto decrypt \"<ciphertext>\" \"<passphrase>\"");
            Console.WriteLine("");
        }
    }
}
