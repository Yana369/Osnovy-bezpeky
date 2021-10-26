using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Lab3._2
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Hash MD5: po1MVkAE7IjUUwu61XxgNg==");
            Console.WriteLine("GUID: {564c8da6-0440-88ec-d453-0bbad57c6036}");
            //Генеруємо список всіх елементів для Brute force
            List<char> Test = new List<char>();
            for (char i = '0'; i <= '9'; i++) { Test.Add(i); }

            Console.WriteLine("\nBruteforce started. Just wait.\n");
            //8 циклів, 7 з них вкладені
            // принцип дії - як в лiчильнику, коли крайнє праве число пробігає всі Test симовли, змінюється попередній символ, і т.д... 
            foreach (char a in Test)
            foreach (char b in Test)
            foreach (char c in Test)
            foreach (char d in Test)
            foreach (char e in Test)
            foreach (char f in Test)
            foreach (char g in Test)
            foreach (char h in Test)
                                        {
                                            //кожен раз створюємо новий екземпляр паролю, з новими a, b, c, d, e, f, g, h значеннями
                                            string password = new string(new[] { a, b, c, d, e, f, g, h });
                                            //обчислюємо MD5 хеш
                                            var md5ForStr = ComputeHashMd5(Encoding.Unicode.GetBytes(password));
                                            //якщо хеш збігається, то пишемо пароль 
                                            if (Convert.ToBase64String(md5ForStr) == "po1MVkAE7IjUUwu61XxgNg==")
                                            //if (guid == Guid.Parse("f5e8fff7-884d-cedd-50d0-67131e83ea22"))
                                            {
                                                Console.WriteLine($"Password find: {password}");
                                                return;
                                            }
                                        }
        }
        static byte[] ComputeHashMd5(byte[] dataForHash)
        {
            using (var md5 = MD5.Create())
            {
                return md5.ComputeHash(dataForHash);
            }
        }
    }
}
