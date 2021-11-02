using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Lab5._5
{
    class Program
    {
        internal static int numberOfRounds;

        static void Main(string[] args)
        {
            
            string choose;
           
            while (true)
            {
                Console.Write("Choose\n1. Register\n2. Login\n");
                do
                { choose = Console.ReadLine(); }
                while ((choose != "1") && (choose != "2"));
                int choice = Convert.ToInt32(choose);
                Console.Write("\n");
                
                switch (choice)
                {
                    case 1:
                        Reg_Log.Register();
                        break;

                    case 2:
                        Reg_Log.Login();
                        break;
                }
            }

        }
    }
    public class SaltedHash
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
                return sha256.ComputeHash(Combine(toBeHashed, salt));
            }
        }

        public static byte[] HashPasswordWithSalt(byte[] toBeHashed, byte[] salt, int iter)
        {
            using (var sha256 = SHA256.Create())
            {
                byte[] hash = sha256.ComputeHash(Combine(toBeHashed, salt));
                for (int i = 0; i < iter; i++)
                {
                    hash = sha256.ComputeHash(hash);
                }
                return hash;
            }
        }
    }
    public class PBKDF2
    {
        public static byte[] GenerateSalt()
        {  
            using (var randomNumberGenerator = new RNGCryptoServiceProvider())
            {
              
                var randomNumber = new byte[32];
                randomNumberGenerator.GetBytes(randomNumber);
                return randomNumber;
            }
        }

        public static byte[] HashPassword(byte[] toBeHashed, byte[] salt, int numberOfRounds, HashAlgorithmName algorithm)
        {
            using (var rfc2898 = new Rfc2898DeriveBytes(toBeHashed, salt, numberOfRounds, algorithm))
            {
                return rfc2898.GetBytes(20);
            }
        }
    }
    public class Reg_Log
    {
      
        private static Dictionary<string, User> USERS = new Dictionary<string, User>();
        
        public static void Register()
        {
            Console.Write("\nlogin: ");
            string login = Console.ReadLine();
            Console.Write("password: ");
            string password = Console.ReadLine();

            byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
            byte[] salt = PBKDF2.GenerateSalt();
            int Rounds = Program.numberOfRounds;
            byte[] passwordHash = SaltedHash.HashPasswordWithSalt(passwordBytes, salt, Rounds);

            Console.WriteLine("\nRegistration complete\n");
            var newUser = new User(login, passwordHash, salt);
            USERS.Add(login, newUser);
        }

        public static void Login()
        {
            Console.Write("\nlogin: ");
            string login = Console.ReadLine();
            Console.Write("password: ");
            string password = Console.ReadLine();

            if (USERS.ContainsKey(login) == true)
            {
                byte[] pass_byte = Encoding.UTF8.GetBytes(password);
                byte[] salt_byte = USERS[login].Salt;
                int iterCount = Program.numberOfRounds;
                byte[] passwordHash = SaltedHash.HashPasswordWithSalt(pass_byte, salt_byte, iterCount);
                string passwordHashString = Convert.ToBase64String(passwordHash);
                if (USERS[login].Password == passwordHashString)
                {
                    Console.WriteLine("\nSuccessful login!\n");
                }
                else
                {
                    Console.WriteLine("\nWrong password!\n");
                }

            }
            else
            {
                Console.WriteLine("\nWrong login!\n");
            }
        }
    }
    public class User
    {
        public string Login;
        public string Password;
        public byte[] Salt;

        public User(string login, byte[] password, byte[] salt)
        {
            Login = login;
            Password = Convert.ToBase64String(password);
            Salt = salt;
        }
    }
}
