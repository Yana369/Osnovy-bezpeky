using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Lab7_2
{
    class Program
    {
        public void AssignNewKey(string publicKeyPath = "publicKeys.xml", string privateKeyPath = "privateKeys.xml")
        {
            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                rsa.PersistKeyInCsp = false;
                File.WriteAllText(publicKeyPath, rsa.ToXmlString(false));
                File.WriteAllText(privateKeyPath, rsa.ToXmlString(true));
            }
        }

        public byte[] EncryptData(byte[] dataToEncrypt, string publicKeyPath = "publicKeys.xml")
        {
            byte[] cipherbytes;
            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                rsa.PersistKeyInCsp = false;
                rsa.FromXmlString(File.ReadAllText(publicKeyPath));
                cipherbytes = rsa.Encrypt(dataToEncrypt, false);
            }
            return cipherbytes;
        }
        public byte[] DecryptData(byte[] dataToEncrypt, string privateKeyPath = "privateKeys.xml")
        {
            byte[] plain;
            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                rsa.PersistKeyInCsp = false;
                rsa.FromXmlString(File.ReadAllText(privateKeyPath));
                plain = rsa.Decrypt(dataToEncrypt, false);
            }
            return plain;
        }
        static void Main(string[] args)
        {
            var rsaParams = new Program();
            const string original = "Hello world!";
            rsaParams.AssignNewKey();
            var encrypted = rsaParams.EncryptData(Encoding.UTF8.GetBytes(original));
            var decrypted = rsaParams.DecryptData(encrypted);
            Console.WriteLine("RSA Encryption Demonstration in .NET");
            Console.WriteLine("------------------------------------");
            Console.WriteLine();
            Console.WriteLine();
            Console.WriteLine(" Original Text = " + original);
            Console.WriteLine(" Encrypted Text = " + Convert.ToBase64String(encrypted));
            Console.WriteLine(" Decrypted Text = " + Encoding.Default.GetString(decrypted));
        }
    }
}
