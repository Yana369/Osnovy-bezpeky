using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Lab8
{
    class Program
    {
        private readonly static string CspContainerName = "RsaContainer";
        public static void AssignNewKey(string publicKeyPath)
        {
            CspParameters cspParameters = new CspParameters(1)
            {
                KeyContainerName = CspContainerName,
                Flags = CspProviderFlags.UseMachineKeyStore,
                ProviderName = "Microsoft Strong Cryptographic Provider"
            };
            using (var rsa = new RSACryptoServiceProvider(2048, cspParameters))
            {
                rsa.PersistKeyInCsp = true;
                File.WriteAllText(publicKeyPath, rsa.ToXmlString(false));
            }
        }
        public static void EncryptData(string publicKeyPath, byte[] dataToEncrypt, string chipherTextPath)
        {
            byte[] chipherBytes;
            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                rsa.PersistKeyInCsp = false;
                rsa.FromXmlString(File.ReadAllText(publicKeyPath));
                chipherBytes = rsa.Encrypt(dataToEncrypt, true);
            }
            File.WriteAllBytes(chipherTextPath, chipherBytes);
        }
        public static byte[] DecryptData(string chipherTextPath)
        {
            byte[] chipherBytes = File.ReadAllBytes(chipherTextPath);
            byte[] plainTextBytes;
            var cspParams = new CspParameters
            {
                KeyContainerName = CspContainerName,
                Flags = CspProviderFlags.UseMachineKeyStore
            };
            using (var rsa = new RSACryptoServiceProvider(2048, cspParams))
            {
                rsa.PersistKeyInCsp = true;
                plainTextBytes = rsa.Decrypt(chipherBytes, true);
            }
            return plainTextBytes;
        }

        static void Main(string[] args)
        {
            AssignNewKey("TsehelnaYana.xml"); 
            Console.WriteLine("Введiть 1 щоб зашифрувати повiдомлення, або 2 щоб розшифрувати повiдомлення: ");
            string temp = Convert.ToString(Console.ReadLine());
            if (temp == "1")
            {
                Console.WriteLine("Введiть повiдомлення для шифрування: ");
                string message = Convert.ToString(Console.ReadLine());
                Console.WriteLine("Введiть iм'я XML-файлу вiдкритого ключа одержувача: ");
                string recPublicKey = Convert.ToString(Console.ReadLine());
                Console.WriteLine("Введiть iм'я файлу, в який потрiбно зашифрувати повiдомлення (dat):");
                string datFile = Convert.ToString(Console.ReadLine());
                EncryptData(recPublicKey, Encoding.UTF8.GetBytes(message), datFile);
                Console.WriteLine("Готово");
            }
            else if (temp == "2")
            {
                Console.WriteLine("Введiть iм’я файлу для розшифрування (dat): ");
                string fileToDecrypt = Convert.ToString(Console.ReadLine());
                Console.WriteLine("Розшифроване повiдомлення: " + Encoding.UTF8.GetString(DecryptData(fileToDecrypt)));
            }
            
        }
    }
}
