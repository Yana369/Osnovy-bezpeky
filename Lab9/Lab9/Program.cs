using System;
using System.IO;
using System.Security.Cryptography;

namespace Lab9
{
    class Program
    {
        //задаємо файли для тексту, підпису та відкритого ключа
        public static string documentFile = "file.txt";
        public static string signatureFile = "sign.bin";
        public static string publicKeyFile = "Tsehelna.xml";

        static void Main(string[] args)
        {
            //меню вибору
            string task;
            while (true)
            {

                Console.Write("Choose\n1. Task 1\n2. Task 2\n");
                do { task = Console.ReadLine(); }
                while ((task != "1") && (task != "2"));

                int task_int = Convert.ToInt32(task);
                Console.Write("\n");
                //зчитуємо текст з файлу
                byte[] document_bytes = File.ReadAllBytes(documentFile);
                //вибираємо завдання
                switch (task_int)
                {
                    case 1:
                        Task1(document_bytes, signatureFile);
                        break;
                    case 2:
                        Task2(document_bytes);
                        break;
                }
            }
        }

        //створення підпису
        private static void Task1(byte[] document_bytes, string signatureFile)
        {
            //створюємо новий підпис за хешом тексту, 
            byte[] signature = ECC.NewSignature(publicKeyFile, document_bytes);
            //виводимо пыдпис на екран
            Console.WriteLine("Signature: " + Convert.ToBase64String(signature) + "\n");
            //і записуємо в файл
            File.WriteAllBytes(signatureFile, signature);
        }

        //перевірка підпису
        private static void Task2(byte[] document_bytes)
        {
            //читаємо файл підпису
            byte[] signature = File.ReadAllBytes(signatureFile);
            //перевіряємо чи збігається підпис
            bool Checked = ECC.CheckSignature(publicKeyFile, document_bytes, signature);
            if (Checked)
            {
                Console.WriteLine("Checked successfully!");
            }
            else
            {
                Console.WriteLine("Wrong phrase!");
            }
        }


        static class ECC
        {
            private readonly static string CspContainerName = "RsaContainer";
            public static byte[] Hash_SHA512(byte[] dataToSign)
            {
                byte[] hashOfData;
                using (var sha512 = SHA512.Create())
                {
                    //рахуємо хеш
                    hashOfData = sha512.ComputeHash(dataToSign);
                }
                //і повертаємо його
                return hashOfData;
            }

            public static byte[] NewSignature(string publicKeyFile, byte[] data)
            {
                //задаємо параметри CSP контейнеру
                var cspParams = new CspParameters
                {
                    KeyContainerName = CspContainerName,
                    Flags = CspProviderFlags.UseMachineKeyStore
                };

                //новий екземпляр RSACryptoServiceProvider
                using (var rsa = new RSACryptoServiceProvider(2048, cspParams))
                {
                    //зберігаємо у CSP контейнері
                    rsa.PersistKeyInCsp = true;

                    //створюємо новий екземпляр RSA PKCS 
                    var rsaFormatter = new RSAPKCS1SignatureFormatter(rsa);
                    //задаємо алгоритм хешування
                    rsaFormatter.SetHashAlgorithm(nameof(SHA512));

                    //отримуємо хеш повідомлення
                    byte[] hashOfData = Hash_SHA512(data);
                    //створюємо підпис хешу повідомлення
                    byte[] signature = rsaFormatter.CreateSignature(hashOfData);

                    //записуємо відкритий ключ
                    File.WriteAllText(publicKeyFile, rsa.ToXmlString(false));
                    //повертаэмо підпис
                    return signature;
                }
            }
            public static bool CheckSignature(string publicKeyFile, byte[] data, byte[] signature)
            {
                //новий екземпляр RSACryptoServiceProvider
                using (var rsa = new RSACryptoServiceProvider(2048))
                {
                    rsa.PersistKeyInCsp = false;
                    //використовуємо відкритий ключ з файлу
                    rsa.FromXmlString(File.ReadAllText(publicKeyFile));

                    //новий екземпляр RSA PKCS для перевірки підпису
                    var rsaDeformatter = new RSAPKCS1SignatureDeformatter(rsa);

                    //задаємо алгоритм хешування
                    rsaDeformatter.SetHashAlgorithm(nameof(SHA512));

                    //отримуємо хеш тексту
                    byte[] hashOfData = Hash_SHA512(data);
                    //повераємо булеве значення результу перевірки
                    return rsaDeformatter.VerifySignature(hashOfData, signature);
                }
            }
        }
    }
}