using System;
using System.Linq;
using System.Text;
using System.Security.Cryptography;
using System.IO;

namespace Lab_2
{
    class Program
    {
        static void Main(string[] args)
        {
            byte[] decData = File.ReadAllBytes("file.txt").ToArray();
            Console.Write("Зчитуємо наше число й виводимо його побайтово: ");
            foreach (byte i in decData)
            {
                Console.Write(i);
                Console.Write(" ");
            }
            Console.WriteLine();
            Console.WriteLine();

            var genPassword = new RNGCryptoServiceProvider();
            byte[] password = new byte[decData.Length];
            genPassword.GetBytes(password);
            Console.Write("Генеруємо ключi для шифрацiї: ");
            foreach (byte i in password)
            {
                Console.Write(i);
                Console.Write(" ");
            }
            Console.WriteLine();
            Console.WriteLine();

            Console.Write("Шифруємо й виводимо байти: ");
            byte[] encData = new byte[decData.Length];
            for (int i = 0; i < decData.Length; i++)
            {
                encData[i] = (byte)(decData[i] ^ password[i]);
            }

            File.WriteAllBytes("encdata.dat", encData);

            Console.WriteLine();
            Console.WriteLine();

            Console.Write("Розшифровуємо зашифрованi байти й виводимо: ");
            byte[] Text = File.ReadAllBytes("encdata.dat").ToArray();
            byte[] decText = new byte[Text.Length];
            for (int i = 0; i < Text.Length; i++)
            {
                decText[i] = (byte)(Text[i] ^ password[i]);
            }


            Console.Write(Encoding.UTF8.GetString(decText));
            Console.WriteLine();
            Console.WriteLine();

        }
    }
}
