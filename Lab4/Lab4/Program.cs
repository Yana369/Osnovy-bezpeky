using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Lab4
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.Write("1. Registartion\n");
            Console.Write("2. Login\n");
            string choose;
            do
            {
                choose = Console.ReadLine();
            }
            while ((choose != "1") && (choose != "2"));
            int choice = Convert.ToInt32(choose);
            Console.Write("\n");

            switch (choice)
            {
                case 1:
                    Register();
                    break;

                case 2:
                    Login();
                    break;
            }

            static byte[] ComputeHmacsha1(byte[] toBeHashed, byte[] key)
            {
                using (var hmac = new HMACSHA1(key))
                {
                    return hmac.ComputeHash(toBeHashed);
                }
            }
            static void Register()
            {
                //Генеруємо крипто ключ для HMAC 
                var randomNumber = new byte[32];
                var rndNumberGenerator = new RNGCryptoServiceProvider();
                rndNumberGenerator.GetBytes(randomNumber);

                //вводимо логін та пароль, які будемо шифрувати
                Console.WriteLine("login: ");
                string login = Console.ReadLine();
                Console.WriteLine("password: ");
                string password = Console.ReadLine();
                //перетворюємо в масив байтів
                byte[] login_bytes = Encoding.UTF8.GetBytes(login);
                byte[] pass_bytes = Encoding.UTF8.GetBytes(password);

                //записуємо в окремі файли HMAC логіну, ключа та пишемо крипто ключ
                File.WriteAllBytes("login.txt", ComputeHmacsha1(login_bytes, randomNumber));
                File.WriteAllBytes("pass.txt", ComputeHmacsha1(pass_bytes, randomNumber));
                File.WriteAllBytes("crypto.key", randomNumber);

                Console.WriteLine("\n\nRegistration sucess!\n\n");

            }

            static void Login()
            {
                //Читаэмо HMAC логіну та паролю а також крипто ключ
                var login_bytes = File.ReadAllBytes("login.txt");
                var pass_bytes = File.ReadAllBytes("pass.txt");
                var key_bytes = File.ReadAllBytes("crypto.key");

                //отримуємо від користувача логін і пароль для перевірки
                Console.WriteLine("Login: ");
                string login_check = Console.ReadLine();
                Console.WriteLine("Password: ");
                string password_check = Console.ReadLine();

                //перетворюємо в масив байтів
                byte[] login_check_bytes = Encoding.UTF8.GetBytes(login_check);
                byte[] pass_check_bytes = Encoding.UTF8.GetBytes(password_check);

                //рахуємо хеш для логіну/паролю, для подальшої перевірки використовуючи ключ
                var login_sha = ComputeHmacsha1(login_check_bytes, key_bytes);
                var pass_sha = ComputeHmacsha1(pass_check_bytes, key_bytes);

                //перевіряємо чи збігаються хеші
                if ((Convert.ToBase64String(login_sha) == Convert.ToBase64String(login_bytes))
                    && (Convert.ToBase64String(pass_sha) == Convert.ToBase64String(pass_bytes)))
                {
                    //якшо збігається і логін і пароль, то Вхід виконаний
                    Console.WriteLine("\n\n=====================================\n");
                    Console.WriteLine("Logined successfully");
                    Console.WriteLine("\n=====================================\n\n");
                }
                else
                {
                    Console.WriteLine("\n\n=====================================\n");
                    Console.WriteLine("Wrong username or password!!!");
                    Console.WriteLine("\n=====================================\n\n");
                }
            }
        }
    }
}
