using System;
using NLog;
using NLog.Config;
using NLog.Targets;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Threading;


namespace Lab13_14
{
    class Program
    {
        private const int HashCount = 25000;
        public static Logger logger;
        static void Main(string[] args)
        {
            //ініціюємо логування
            InitLogger();
            //викликаємо функції реєстрації, входу, перевірки ролей
            Register();
            LogIn();
        }
        static void InitLogger()
        {
            //створюємо екземпляр класу параметрів логування
            var config = new LoggingConfiguration();

            //екземпляр класу виводу в консоль
            var consoleTarget = new ColoredConsoleTarget("target1")
            {
                Layout = @"${date:format=HH\:mm\:ss} ${level} ${message} ${exception}"
            };
            //додаємо ціль до конфігурації
            config.AddTarget(consoleTarget);

            //екземпляр класу виводу в файл
            var fileTarget = new FileTarget("target2")
            {
                //назва файлу логу
                FileName = "Program.log",
                Layout = "${longdate} ${level} ${message}  ${exception} ${callsite} ${callsite-linenumber}"
            };
            //додаємо ціль до конфігурації
            config.AddTarget(fileTarget);

            //додаємо 3 рівні до файлу
            config.AddRuleForOneLevel(LogLevel.Warn, fileTarget);
            config.AddRuleForOneLevel(LogLevel.Error, fileTarget);
            config.AddRuleForOneLevel(LogLevel.Fatal, fileTarget);

            //додаємо всі рівні в консоль
            config.AddRuleForAllLevels(consoleTarget);

            //вписуємо створену конфікурацію в LogManager
            LogManager.Configuration = config;

            logger = LogManager.GetLogger("Example");
        }
        //функція реєстрації
        static void Register()
        {
            //вводимо логін/пароль для реєстрації і виводимо повідомлення про отримання данних
            Console.Write("login -> ");
            string login = Console.ReadLine();
            logger.Debug("Recieved login");
            Console.Write("password -> ");
            string password = Console.ReadLine();
            logger.Debug("Recieved password");

            //задаємо ролі і виводимо повідомлення про отримання
            Console.Write("Write your role -> ");
            string role = Console.ReadLine();
            logger.Debug("Recieved role");
            Console.WriteLine();

            var roles = new string[] { role };

            //виводимо отриману для реєстрації інформацію
            logger.Info($"Recieved registartion information:\nlogin={login}");

            //реєструємо користувача по отриманим данним
            var user = Protector.Register(login, password, roles);
            Console.WriteLine("Your role(s): " + user.Roles[0] + "\n");

            //виводимо результат перевірки, чи записалися данні про реєстрацію
            if (user != null)
            {
                logger.Info($"{login} registered");
            }
            else
            {
                logger.Error($"Error during registartion {login}");
            }

        }
        static void LogIn()
        {
            //звпитуємо логін/пароль на перевірку і виводимо повідомлення про отримання данних
            Console.Write("login: ");
            string login = Console.ReadLine();
            logger.Debug("Recieved login");
            Console.Write("password: ");
            string password = Console.ReadLine();
            logger.Debug("Recieved password");
            Console.WriteLine();

            //якщо істина, то вхід успішний
            if (Protector.LogIn(login, password))
            {
                Console.WriteLine("Login successful!");
                logger.Info($"{login} logined!");

            }
            else
            {
                Console.WriteLine("Wrong user/pass");
                logger.Fatal($"Wrong user/pass: login={login}");
            }
            //перевіряємо права
            CheckRights();
        }
        static void CheckRights()
        {
            //в залежності від ролі виконуємо дії, в данних випадках виводимо назву ролі і логуємо
            if (Thread.CurrentPrincipal.IsInRole("root"))
            {
                Console.WriteLine("Your role: root");
                logger.Info("root logined");
            }
            else if (Thread.CurrentPrincipal.IsInRole("uzver"))
            {
                Console.WriteLine("Your role: uzver!!!");
                logger.Info("uzver logined to system");
            }
            else if (Thread.CurrentPrincipal.IsInRole("editor"))
            {
                Console.Write("Your role: editor");
                logger.Info("Editor logined, waiting for document changes");
            }
            else
            {
                Console.WriteLine("Unknown uzver");
                logger.Warn("Alert! Unknown user");
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
                    //виводимо результат в трасування
                    logger.Trace("Password salt generated");
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
                    //виводимо результат в трасування
                    logger.Trace("Salted hash generated");
                    return sha256.ComputeHash(Combine(toBeHashed, salt));
                }

            }
            public static byte[] HashPasswordWithSalt(byte[] toBeHashed, byte[] salt, int iterationsCount)
            {
                using (var sha256 = SHA256.Create())
                {
                    byte[] hash = sha256.ComputeHash(Combine(toBeHashed, salt));
                    for (int i = 0; i < iterationsCount; i++)
                    {
                        hash = sha256.ComputeHash(Combine(toBeHashed, salt));
                    }
                    //виводимо результат в трасування
                    logger.Trace($"Salted {iterationsCount} times hash generated");
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
                //перетворюємо данні в масиви байтів і виводимо проміжкові результати виконання
                byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
                logger.Debug("Converted password");
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
                //виводимо інформацію про успішну реєстрацію користувача
                logger.Info("Created new user");
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
                    //виводимо інформацію про виконання зчитування ролей і успішний логін
                    logger.Debug("Storaged principal");
                    logger.Trace("Logined successfully");
                    return true;
                }

                return false;
            }
            //функція перевірки паролю
            private static bool CheckPassword(string userName, string password)
            {
                if (_users.ContainsKey(userName))
                {
                    //говоримо, що логін правильний
                    logger.Info("Login correct");

                    //перетворюємо данні у масиви байтів
                    byte[] pass_byte = Encoding.UTF8.GetBytes(password);
                    logger.Debug("Converted password to array");
                    byte[] saltBytes = _users[userName].Salt;
                    //виводимо інформацію про запис солі в контейнер
                    logger.Debug("Recieved salt from container");
                    byte[] passwordHash = SaltedHash.HashPasswordWithSalt(pass_byte, saltBytes, HashCount);
                    //перетворюємо хеш на стрічку
                    string passwordHashString = Convert.ToBase64String(passwordHash);

                    logger.Debug("Passwords will be compared...");

                    //повертаємо результат перевірки хешу
                    return _users[userName].PasswordHash == passwordHashString;
                }
                else
                {
                    //користувача не існує
                    Console.WriteLine("User login not exist!");
                    //виводимо попередження про неправильний логін
                    logger.Warn("Login incorrect");
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

   
