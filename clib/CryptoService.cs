using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.IO;

namespace clib
{
    public class CryptoService
    {
        private const int keysize = 256;

        public struct EncryptedBundle
        {
            public string EncryptedKey { get; set; }
            public string EncryptedString { get; set; }
        }

        public static EncryptedBundle EncryptString(string plainText, int keyLength, string initVector)
        {
            string passPhrase = GenerateKey(keyLength);
            byte[] initVectorBytes = Encoding.UTF8.GetBytes(initVector);
            byte[] plainTextBytes = Encoding.UTF8.GetBytes(plainText);
            PasswordDeriveBytes password = new PasswordDeriveBytes(passPhrase, null);
            byte[] keyBytes = password.GetBytes(keysize / 8);
            RijndaelManaged symmetricKey = new RijndaelManaged();
            symmetricKey.Mode = CipherMode.CBC;
            ICryptoTransform encryptor = symmetricKey.CreateEncryptor(keyBytes, initVectorBytes);
            MemoryStream memoryStream = new MemoryStream();
            CryptoStream cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write);
            cryptoStream.Write(plainTextBytes, 0, plainTextBytes.Length);
            cryptoStream.FlushFinalBlock();
            byte[] cipherTextBytes = memoryStream.ToArray();
            memoryStream.Close();
            cryptoStream.Close();
            EncryptedBundle eb = new EncryptedBundle();
            eb.EncryptedString = Convert.ToBase64String(cipherTextBytes);
            eb.EncryptedKey = EncryptKey(passPhrase);
            return eb;
        }

        public static string DecryptString(EncryptedBundle eb, string initVector)
        {
            string passPhrase = DecryptKey(eb.EncryptedKey);
            string cipherText = eb.EncryptedString;
            byte[] initVectorBytes = Encoding.UTF8.GetBytes(initVector);
            byte[] cipherTextBytes = Convert.FromBase64String(cipherText);
            PasswordDeriveBytes password = new PasswordDeriveBytes(passPhrase, null);
            byte[] keyBytes = password.GetBytes(keysize / 8);
            RijndaelManaged symmetricKey = new RijndaelManaged();
            symmetricKey.Mode = CipherMode.CBC;
            ICryptoTransform decryptor = symmetricKey.CreateDecryptor(keyBytes, initVectorBytes);
            MemoryStream memoryStream = new MemoryStream(cipherTextBytes);
            CryptoStream cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read);
            byte[] plainTextBytes = new byte[cipherTextBytes.Length];
            int decryptedByteCount = cryptoStream.Read(plainTextBytes, 0, plainTextBytes.Length);
            memoryStream.Close();
            cryptoStream.Close();
            return Encoding.UTF8.GetString(plainTextBytes, 0, decryptedByteCount);
        }

        private static string EncryptKey(string key)
        {
 
            return EncryptXOR(ChangePosition(key.Substring(0, key.Length / 4))+ChangeCase(key.Substring(key.Length/4, key.Length / 4))+InvertMembers(key.Substring((key.Length / 4)*2, key.Length / 4))+EncryptXOR(key.Substring((key.Length / 4) * 3, (key.Length / 4) + (key.Length % 4)), (key.Length)*3), key.Length);

        }

        private static string DecryptKey(string keyXOR)
        {
            string key = EncryptXOR(keyXOR, keyXOR.Length);
            return (ReversePosition(key.Substring(0, key.Length / 4)) + ChangeCase(key.Substring(key.Length / 4, key.Length / 4)) + InvertMembers(key.Substring((key.Length / 4) * 2, key.Length / 4)) + EncryptXOR(key.Substring((key.Length / 4) * 3, (key.Length / 4) + (key.Length % 4)), (keyXOR.Length)*3));

        }

        private static string GenerateKey (int KeyLength)
        {
            var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";
            char[] stringChars = new char[KeyLength];
            Random random = new Random();
            for (int i = 0; i < stringChars.Length; i++)
            {
                stringChars[i] = chars[random.Next(chars.Length)];
            }
            string key = new String(stringChars);
            return key;
        }

        private static string ChangePosition(string stringLine)
        {
            int k;
            string resultLine="";
            for (int i = 0; i < 3; i++)
            {
                k = 0;
                resultLine = "";
                while (k < stringLine.Length/2)
                {
                    resultLine += stringLine[stringLine.Length - k - 1];
                    resultLine += stringLine[k];
                    k++;
                }
                if (stringLine.Length%2 != 0 )
                    resultLine += stringLine[stringLine.Length / 2];

                stringLine = resultLine;
            }
            return resultLine;
        }

        private static string ReversePosition(string stringLine)
        {
            int k;
            string resultLine = "";
            for (int i = 0; i < 3; i++)
            {
                k = 0;
                resultLine = "";
                if (stringLine.Length % 2 == 0)
                {
                    while (k < stringLine.Length / 2)
                    {
                        resultLine += stringLine[(2 * k + 1)];
                        k++;
                    }
                    while (k < stringLine.Length)
                    {
                        resultLine += stringLine[((stringLine.Length * 2 - 2) - 2 * k)];
                        k++;
                    }
                }
                else
                {
                    while (k < stringLine.Length / 2)
                    {
                        resultLine += stringLine[(2 * k + 1)];
                        k++;
                    }
                    resultLine += stringLine[stringLine.Length - 1];
                    while (k < stringLine.Length - 1)
                    {
                        resultLine += stringLine[(((stringLine.Length-1) * 2 - 2) - 2 * k)];
                        k++;
                    }
                }
                stringLine = resultLine;
            }
            return resultLine;
        }


        private static string ChangeCase(string stringLine)
        {
            int i = 0;
            string resultLine = "";
            while (i < stringLine.Length)
            {
                if (Char.IsUpper(stringLine[i]))
                {
                    resultLine += Char.ToLower(stringLine[i]);
                }
                else if (Char.IsLower(stringLine[i]))
                {
                    resultLine += Char.ToUpper(stringLine[i]);
                }
                else
                {
                    resultLine += stringLine[i];
                }
                i++;
            }
            return resultLine;

        }
        
        private static string InvertMembers(string stringLine)
        {
            string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";
            int i = 0;
            string resultLine = "";
            while (i < stringLine.Length)
            {
                resultLine += chars[(chars.Length - chars.IndexOf(stringLine[i]) - 1)];
                i++;
            }

            return resultLine;
        }
        
        private static string EncryptXOR(string stringLine, int key)
        {
            string resultLine = "";
            for (int i = 0; i < stringLine.Length; i++)
            {
                resultLine += (char)(stringLine[i] ^ key);
            }
            return resultLine;
        }

    }
}
