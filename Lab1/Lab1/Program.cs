using System;
using System.Security.Cryptography;

namespace Lab1
{
    class Program
    {
        static void Main(string[] args)
        {
            {
                Random random = new Random(1357);
                for (int i = 0; i < 5; i++)
                {
                    Console.WriteLine(random.Next(0, 100));
                }
                Console.WriteLine("--------------------");
                Random random1 = new Random(1357);
                for (int i = 0; i < 5; i++)
                {
                    Console.WriteLine(random1.Next(0, 100));
                }
                Console.WriteLine("--------------------");
                Random random2 = new Random(2002);
                for (int i = 0; i < 5; i++)
                {
                    Console.WriteLine(random2.Next(0, 100));
                }
                Console.WriteLine("--------------------");
                var rndNumberGeneration = new RNGCryptoServiceProvider();
                var randomNumber = new byte[10];
                for (int i = 0; i < 10; i++)
                {
                    rndNumberGeneration.GetBytes(randomNumber);
                    string textRNGs = Convert.ToBase64String(randomNumber);
                    Console.WriteLine(textRNGs);
                }

            }
        }
    }
}
