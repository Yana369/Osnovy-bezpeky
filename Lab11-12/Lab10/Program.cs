using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Threading;

namespace Lab10
{
    class Program
    {
        private const int HashCount = 25000;
        static void Main(string[] args)
        {
            //викликаємо функції реєстрації, входу, перевірки ролей
            for(int i = 0; i < 4; i++)
            {
                Register();
                LogIn();
            }
            
        }

        //функція реєстрації
        static void Register()
        {
            //вводимо логін/пароль для реєстрації
            Console.Write("login -> ");
            string login = Console.ReadLine();
            Console.Write("password -> ");
            string password = Console.ReadLine();

            //задаємо ролі
            Console.Write("Write your role -> ");
            string role = Console.ReadLine();
            Console.WriteLine();

            var roles = new string[] { role };
            //реєструємо користувача по отриманим данним
            var user = Protector.Register(login, password, roles);
            Console.WriteLine("Your role(s): " + user.Roles[0] + "\n");

        }
        static void LogIn()
        {
            //звпитуємо логін/пароль на перевірку
            Console.Write("login: ");
            string login = Console.ReadLine();
            Console.Write("password: ");
            string password = Console.ReadLine();
            Console.WriteLine();
            //якщо істина, то вхід успішний
            if (Protector.LogIn(login, password))
            {
                Console.WriteLine("Login successful!");
                CheckRights();
            }
            else
            {
                Console.WriteLine("Wrong user/pass");
            }
        }
        static void CheckRights()
        {
            //в залежності від ролі виконуємо дії, в данних випадках виводимо назву ролі
            if (Thread.CurrentPrincipal.IsInRole("root"))
            {
                Console.WriteLine("Your role: root");
            }
            else if (Thread.CurrentPrincipal.IsInRole("user"))
            {
                Console.WriteLine("Your role: user!!!");
            }
            else if (Thread.CurrentPrincipal.IsInRole("editor"))
            {
                Console.Write("Your role: editor");
            }
            else
            {
                Console.WriteLine("Unknown user");
            }
        }

        class SaltedHash
        {
            public static byte[] GenerateSalt()
            {
                const int saltLength = 32;
                using (var randomNumberGenerator = new RNGCryptoServiceProvider())
                {
                    var randomNumber = new byte[saltLength];
                    randomNumberGenerator.GetBytes(randomNumber);
                    return randomNumber;
                }
            }
            private static byte[] Combine(byte[] first, byte[] second)
            {
                var ret = new byte[first.Length + second.Length];
                Buffer.BlockCopy(first, 0, ret, 0, first.Length);
                Buffer.BlockCopy(second, 0, ret, first.Length, second.Length);
                return ret;
            }
            public static byte[] HashPasswordWithSalt(byte[] toBeHashed, byte[] salt)
            {
                using (var sha256 = SHA256.Create())
                {
                    // считаем хэш от объединенного массива байтов из пароля и хэша
                    return sha256.ComputeHash(Combine(toBeHashed, salt));
                }
            }
            public static byte[] HashPasswordWithSalt(byte[] toBeHashed, byte[] salt, int iterationsCount)
            {
                // Тоже самое, что и в методе выше, но мы не 1 раз хэшируем, а очень много раз :)
                using (var sha256 = SHA256.Create())
                {
                    byte[] hash = sha256.ComputeHash(Combine(toBeHashed, salt));
                    for (int i = 0; i < iterationsCount; i++)
                    {
                        hash = sha256.ComputeHash(Combine(toBeHashed, salt));
                    }

                    return hash;
                }
            }
        }
        class Protector
        {
            //словник власного класу, що зберігає логін, хеш пароль, сіль, ролі
            public static Dictionary<string, User> _users = new Dictionary<string, User>();
            //функція реєстрації
            public static User Register(string userName, string password, string[] roles = null)
            {
                //перетворюємо данні в масиви байтів
                byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
                byte[] saltBytes = SaltedHash.GenerateSalt();
                byte[] passwordHash = SaltedHash.HashPasswordWithSalt(passwordBytes, saltBytes, HashCount);
                //хеш перетворюємо в стрічку
                string passwordHashString = Convert.ToBase64String(passwordHash);
                Console.WriteLine("Registration complete");
                //створюємо новий екземпляр користувача і заносимо в нього параметри
                var newUser = new User
                {
                    Login = userName,
                    PasswordHash = passwordHashString,
                    Salt = saltBytes,
                    Roles = roles
                };
                //запусуємо ці данні в наш клас
                _users.Add(userName, newUser);
                return newUser;
            }
            public static bool LogIn(string userName, string password)
            {
                //перевіряємо пароль
                if (CheckPassword(userName, password))
                {
                    var identity = new GenericIdentity(userName, "OIBAuth");
                    //отримуємо ролі
                    var principal = new GenericPrincipal(identity, _users[userName].Roles);
                    //записуємо їх як поточні
                    Thread.CurrentPrincipal = principal;

                    return true;
                }

                return false;
            }
            //функція перевірки паролю
            private static bool CheckPassword(string userName, string password)
            {
                if (_users.ContainsKey(userName))
                {
                    //перетворюємо данні у масиви байтів
                    byte[] pass_byte = Encoding.UTF8.GetBytes(password);
                    byte[] saltBytes = _users[userName].Salt;
                    byte[] passwordHash = SaltedHash.HashPasswordWithSalt(pass_byte, saltBytes, HashCount);
                    //перетворюємо хеш на стрічку
                    string passwordHashString = Convert.ToBase64String(passwordHash);
                    //повертаємо результат перевірки хешу
                    return _users[userName].PasswordHash == passwordHashString;
                }
                else
                {
                    //користувача не існує
                    Console.WriteLine("User login not exist!");
                    return false;
                }
            }
        }
        class User
        {
            public string Login { get; set; }
            public string PasswordHash { get; set; }
            public byte[] Salt { get; set; }
            public string[] Roles { get; set; }
        }

    }
}
