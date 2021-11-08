using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Lab6._2
{
    class Program
    {
        public static int numberOfRounds = 250000;
        static void Main(string[] args)
        {
            var aesChipher = new aesChipher();
            var desChipher = new desChipher();
            var trippleDES = new trippleDES();

            Console.Write("Enter password:");
            string original = Console.ReadLine();
            byte[] ori_bytes = Encoding.ASCII.GetBytes(original);
            byte[] key_aes = PBKDF2.Generator(ori_bytes, 32);
            byte[] iv_aes = PBKDF2.Generator(ori_bytes, 16);
            byte[] key_des = PBKDF2.Generator(ori_bytes, 8);
            byte[] iv_des = PBKDF2.Generator(ori_bytes, 8);
            byte[] key_tdes = PBKDF2.Generator(ori_bytes, 24);
            byte[] iv_tdes = PBKDF2.Generator(ori_bytes, 8);

            var encrypted_aes = aesChipher.Encrypt(ori_bytes, key_aes, iv_aes);
            var decrypted_aes = aesChipher.Decrypt(encrypted_aes, key_aes, iv_aes);
            var decryptedMessage_aes = Encoding.UTF8.GetString(decrypted_aes);
            Console.WriteLine("\nAES Encryption in .NET");
            Console.WriteLine("----------------------\n");
            Console.WriteLine("Original Text = " + original);
            Console.WriteLine("Encrypted Text = " + Convert.ToBase64String(encrypted_aes));
            Console.WriteLine("Decrypted Text = " + decryptedMessage_aes + "\n\n\n");

           
            var encrypted_des = desChipher.Encrypt(ori_bytes, key_des, iv_des);
            var decrypted_des = desChipher.Decrypt(encrypted_des, key_des, iv_des);
            var decryptedMessage_des = Encoding.UTF8.GetString(decrypted_des);
            Console.WriteLine("DES Encryption in .NET");
            Console.WriteLine("----------------------\n");
            Console.WriteLine("Original Text = " + original);
            Console.WriteLine("Encrypted Text = " + Convert.ToBase64String(encrypted_des));
            Console.WriteLine("Decrypted Text = " + decryptedMessage_des + "\n\n\n");

           
            var encrypted_tdes = trippleDES.Encrypt(ori_bytes, key_tdes, iv_tdes);
            var decrypted_tdes = trippleDES.Decrypt(encrypted_tdes, key_tdes, iv_tdes);
            var decryptedMessage_tdes = Encoding.UTF8.GetString(decrypted_tdes);
            Console.WriteLine("Triple DES Encryption in .NET");
            Console.WriteLine("----------------------\n");
            Console.WriteLine("Original Text = " + original);
            Console.WriteLine("Encrypted Text = " + Convert.ToBase64String(encrypted_tdes));
            Console.WriteLine("Decrypted Text = " + decryptedMessage_tdes);
            Console.ReadKey();
        }

        class aesChipher
        {
           
            public byte[] GenerateRandomNumber(int length)
            {
                using (var randomNumberGenerator = new RNGCryptoServiceProvider())
                {
                    
                    var randomNumber = new byte[length];
                    randomNumberGenerator.GetBytes(randomNumber);
                    return randomNumber;
                }
            }
            public byte[] Encrypt(byte[] dataToEncrypt, byte[] key, byte[] iv)
            {
                using (var aes = new AesCryptoServiceProvider())
                {
                    aes.Mode = CipherMode.CBC;
                    aes.Padding = PaddingMode.PKCS7;
                    aes.Key = key;
                    aes.IV = iv;
                    using (var memoryStream = new MemoryStream())
                    {
                        var cryptoStream = new CryptoStream(memoryStream, aes.CreateEncryptor(), CryptoStreamMode.Write);
                        cryptoStream.Write(dataToEncrypt, 0, dataToEncrypt.Length);
                        cryptoStream.FlushFinalBlock();
                        return memoryStream.ToArray();
                    }
                }
            }
            public byte[] Decrypt(byte[] dataToDecrypt, byte[] key, byte[] iv)
            {
                using (var aes = new AesCryptoServiceProvider())
                {
                    aes.Mode = CipherMode.CBC;
                    aes.Padding = PaddingMode.PKCS7;
                    aes.Key = key;
                    aes.IV = iv;
                    using (var memoryStream = new MemoryStream())
                    {
                        var cryptoStream = new CryptoStream(memoryStream, aes.CreateDecryptor(), CryptoStreamMode.Write);
                        cryptoStream.Write(dataToDecrypt, 0, dataToDecrypt.Length);
                        cryptoStream.FlushFinalBlock();
                        return memoryStream.ToArray();
                    }
                }
            }
        }
        class desChipher
        {
            public byte[] GenerateRandomNumber(int length)
            {
                using (var randomNumberGenerator = new RNGCryptoServiceProvider())
                {
                    var randomNumber = new byte[length];
                    randomNumberGenerator.GetBytes(randomNumber);
                    return randomNumber;
                }
            }
            public byte[] Encrypt(byte[] dataToEncrypt, byte[] key, byte[] iv)
            {
                using (var des = new DESCryptoServiceProvider())
                {
                    des.Mode = CipherMode.CBC;
                    des.Padding = PaddingMode.Zeros;
                    des.Key = key;
                    des.IV = iv;
                    using (var memoryStream = new MemoryStream())
                    {
                        var cryptoStream = new CryptoStream(memoryStream, des.CreateEncryptor(), CryptoStreamMode.Write);
                        cryptoStream.Write(dataToEncrypt, 0, dataToEncrypt.Length);
                        cryptoStream.FlushFinalBlock();
                        return memoryStream.ToArray();
                    }
                }
            }
            public byte[] Decrypt(byte[] dataToDecrypt, byte[] key, byte[] iv)
            {
                using (var des = new DESCryptoServiceProvider())
                {
                    des.Mode = CipherMode.CBC;
                    des.Padding = PaddingMode.Zeros;
                    des.Key = key;
                    des.IV = iv;
                    using (var memoryStream = new MemoryStream())
                    {
                        var cryptoStream = new CryptoStream(memoryStream, des.CreateDecryptor(), CryptoStreamMode.Write);
                        cryptoStream.Write(dataToDecrypt, 0, dataToDecrypt.Length);
                        cryptoStream.FlushFinalBlock();
                        return memoryStream.ToArray();
                    }
                }
            }
        }
        class trippleDES
        {
           
            public byte[] GenerateRandomNumber(int length)
            {
                using (var randomNumberGenerator = new RNGCryptoServiceProvider())
                {
                    var randomNumber = new byte[length];
                    randomNumberGenerator.GetBytes(randomNumber);
                    return randomNumber;
                }
            }
            public byte[] Encrypt(byte[] dataToEncrypt, byte[] key, byte[] iv)
            {
              
                using (var des = new TripleDESCryptoServiceProvider())
                {
                    des.Mode = CipherMode.CBC;
                    des.Padding = PaddingMode.PKCS7;
                    des.Key = key;
                    des.IV = iv;
                    using (var memoryStream = new MemoryStream())
                    {
                        //новий екземпляр потоку криптографічних перетворень
                        var cryptoStream = new CryptoStream(memoryStream, des.CreateEncryptor(), CryptoStreamMode.Write);
                        //записуємо байти для обробки, зміщення, довжину масиву
                        cryptoStream.Write(dataToEncrypt, 0, dataToEncrypt.Length);
                        //оновлюємо данні з буфферу і чистимо його
                        cryptoStream.FlushFinalBlock();
                        //повертаємо дешифроване повідомлення
                        return memoryStream.ToArray();
                    }
                }
            }
            public byte[] Decrypt(byte[] dataToDecrypt, byte[] key, byte[] iv)
            {
                using (var des = new TripleDESCryptoServiceProvider())
                {
                    des.Mode = CipherMode.CBC;
                    des.Padding = PaddingMode.PKCS7;
                    des.Key = key;
                    des.IV = iv;
                    using (var memoryStream = new MemoryStream())
                    {
                        var cryptoStream = new CryptoStream(memoryStream, des.CreateDecryptor(), CryptoStreamMode.Write);
                        cryptoStream.Write(dataToDecrypt, 0, dataToDecrypt.Length);
                        cryptoStream.FlushFinalBlock();
                        return memoryStream.ToArray();
                    }
                }
            }
        }
        class PBKDF2
        {
            public static byte[] GenerateSalt(int length)
            {  
                using (var randomNumberGenerator = new RNGCryptoServiceProvider())
                {
                    var randomNumber = new byte[length];
                    randomNumberGenerator.GetBytes(randomNumber);
                    return randomNumber;
                }
            }
            public static byte[] Generator(byte[] toBeHashed, int length)
            {
                byte[] salt = GenerateSalt(16);
                using (var rfc2898 = new Rfc2898DeriveBytes(toBeHashed, salt, numberOfRounds))
                {
                    return rfc2898.GetBytes(length);
                }
            }
        }
    }
}
