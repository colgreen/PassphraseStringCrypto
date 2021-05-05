using System;
using System.Security.Cryptography;
using System.Text;

namespace PassphraseStringCrypto
{
    class Program
    {
        const int __iterations = 2_000_000;

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
                byte[] ciphertext = Encrypt(text, passphrase);
                DumpBinaryToConsole(ciphertext);
            }
            else
            {
                string decryptedString = Decrypt(text, passphrase);
                Console.WriteLine(decryptedString);
            }




            //string stringToEncrypt = "0123456789012345678901234567890123456789012345678901";
            //string passphrase = "correct horse battery staple";
            
            


            //string abase64 = "LC^ph$ZAFPGiZPCD<X/XeN<iepQANG&AhHw5Q$sX3nMtG^s46CbqG8swk5szZwvwm5qJEtp38tn8wjC4Ud7Yft9EKi<6gRDRi3DLITZP;NQ&$y42AWHgaSXi";
            //string decryptedString = Decrypt(abase64, passphrase);

        }











        private static byte[] Encrypt(string stringToEncrypt, string passphrase)
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

            return saltAndCiphertext;
        }



        private static string Decrypt(string abase64ToDecrypt, string passphrase)
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

        private static string DumpBinaryToConsole(byte[] data)
        {
            string abase64 = Base64Utils.ToAlternativeBase64(data);

            for(int i=0; i < abase64.Length; i += 8)
            {
                int len = Math.Min(8, abase64.Length - i);
                var span = abase64.AsSpan(i, len);
                Console.Write(span.ToArray());
                Console.Write(" ");
            }

            Console.WriteLine();
            Console.WriteLine();
            Console.WriteLine(abase64);

            return abase64;
        }
    }
}
