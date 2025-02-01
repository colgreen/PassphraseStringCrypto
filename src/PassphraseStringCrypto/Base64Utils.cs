using System;

namespace PassphraseStringCrypto;

internal static class Base64Utils
{
    public static string ToAlternativeBase64(byte[] data)
    {
        string base64 = Convert.ToBase64String(data);

        char[] arr = base64.ToCharArray();

        for(int i=0; i < arr.Length; i++)
        {
            ref char ch = ref arr[i];
            switch(ch)
            {
                case '0': 
                    ch = '$';
                    break;
                case '1':
                    ch = '#';
                    break;
                case 'O':
                    ch = ';';
                    break;
                case 'l':
                    ch = '~';
                    break;
                case 'o':
                    ch = '^';
                    break;
            }
        }

        return new string(arr);
    }

    public static byte[] FromAlternativeBase64(string abase64)
    {
        char[] arr = abase64.ToCharArray();

        for(int i=0; i < arr.Length; i++)
        {
            ref char ch = ref arr[i];
            switch(ch)
            {
                case '$': 
                    ch = '0';
                    break;
                case '#': 
                    ch = '1';
                    break;
                case ';': 
                    ch = 'O';
                    break;
                case '~': 
                    ch = 'l';
                    break;
                case '^': 
                    ch = 'o';
                    break;

                // Test for invalid chars, i.e., the standard base64 characters that
                // are substituted in our alternative base64 scheme.
                case '0':
                case '1':
                case 'O':
                case 'l':
                case 'o':
                    throw new FormatException("Invalid chars for alternative base64 string.");
            }
        }

        return Convert.FromBase64CharArray(arr, 0, arr.Length);
    }
}
