using System;
using System.Security.Cryptography;
using System.Text;

namespace Lab3._1
{
    class Program
    {
        static byte[] ComputeHashMd5(byte[] dataForHash)

        {
            using (var md5 = MD5.Create())
            {
                return md5.ComputeHash(dataForHash);
            }
        }

        public static byte[] ComputeHashSha1(byte[] toBeHashed)
        {
            using (var sha1 = SHA1.Create())
            {
                return sha1.ComputeHash(toBeHashed);
            }
        }

        public static byte[] ComputeHashSha256(byte[] toBeHashed)
        {
            using (var sha256 = SHA256.Create())
            {
                return sha256.ComputeHash(toBeHashed);
            }
        }

        public static byte[] ComputeHashSha384(byte[] toBeHashed)
        {
            using (var sha384 = SHA384.Create())
            {
                return sha384.ComputeHash(toBeHashed);
            }
        }

        public static byte[] ComputeHashSha512(byte[] toBeHashed)
        {
            using (var sha512 = SHA512.Create())
            {
                return sha512.ComputeHash(toBeHashed);
            }
        }


        static void Main(string[] args)
        {
            const string str1 = "Hello World!";
            const string str2 = "Hello World!";
            const string str3 = "HellO World!";

            var md5ForStr1 = ComputeHashMd5(Encoding.Unicode.GetBytes(str1));
            var md5ForStr2 = ComputeHashMd5(Encoding.Unicode.GetBytes(str2));
            var md5ForStr3 = ComputeHashMd5(Encoding.Unicode.GetBytes(str3));

            Guid guid1 = new Guid(md5ForStr1),
                guid2 = new Guid(md5ForStr2),
                guid3 = new Guid(md5ForStr3);


            Console.WriteLine($"Str:{str1}");
            Console.WriteLine($"Hash Md5:{Convert.ToBase64String(md5ForStr1)}");
            Console.WriteLine($"GUID:{guid1}");
            Console.WriteLine("");
            Console.WriteLine($"Str:{str2}");
            Console.WriteLine($"Hash Md5:{Convert.ToBase64String(md5ForStr2)}");
            Console.WriteLine($"GUID:{guid2}");
            Console.WriteLine("");
            Console.WriteLine($"Str:{str3}");
            Console.WriteLine($"Hash Md5:{Convert.ToBase64String(md5ForStr3)}");
            Console.WriteLine($"GUID:{guid3}");
            Console.WriteLine("");

            var sha1ForStr1 = ComputeHashSha1(Encoding.Unicode.GetBytes(str1));
            var sha1ForStr2 = ComputeHashSha1(Encoding.Unicode.GetBytes(str2));
            var sha1ForStr3 = ComputeHashSha1(Encoding.Unicode.GetBytes(str3));

            Console.WriteLine($"Str:{str1}");
            Console.WriteLine($"Hash sha1:{Convert.ToBase64String(sha1ForStr1)}");

            Console.WriteLine("");
            Console.WriteLine($"Str:{str2}");
            Console.WriteLine($"Hash sha1:{Convert.ToBase64String(sha1ForStr2)}");

            Console.WriteLine("");
            Console.WriteLine($"Str:{str3}");
            Console.WriteLine($"Hash sha1:{Convert.ToBase64String(sha1ForStr3)}");

            Console.WriteLine("");

            var sha256ForStr1 = ComputeHashSha256(Encoding.Unicode.GetBytes(str1));
            var sha256ForStr2 = ComputeHashSha256(Encoding.Unicode.GetBytes(str2));
            var sha256ForStr3 = ComputeHashSha256(Encoding.Unicode.GetBytes(str3));

            Console.WriteLine($"Str:{str1}");
            Console.WriteLine($"Hash sha256:{Convert.ToBase64String(sha256ForStr1)}");

            Console.WriteLine("");
            Console.WriteLine($"Str:{str2}");
            Console.WriteLine($"Hash sha256:{Convert.ToBase64String(sha256ForStr2)}");

            Console.WriteLine("");
            Console.WriteLine($"Str:{str3}");
            Console.WriteLine($"Hash sha256:{Convert.ToBase64String(sha256ForStr3)}");

            Console.WriteLine("");

            var sha384ForStr1 = ComputeHashSha384(Encoding.Unicode.GetBytes(str1));
            var sha384ForStr2 = ComputeHashSha384(Encoding.Unicode.GetBytes(str2));
            var sha384ForStr3 = ComputeHashSha384(Encoding.Unicode.GetBytes(str3));

            Console.WriteLine($"Str:{str1}");
            Console.WriteLine($"Hash sha384:{Convert.ToBase64String(sha384ForStr1)}");

            Console.WriteLine("");
            Console.WriteLine($"Str:{str2}");
            Console.WriteLine($"Hash sha384:{Convert.ToBase64String(sha384ForStr2)}");

            Console.WriteLine("");
            Console.WriteLine($"Str:{str3}");
            Console.WriteLine($"Hash sha384:{Convert.ToBase64String(sha384ForStr3)}");

            Console.WriteLine("");

            var sha512ForStr1 = ComputeHashSha512(Encoding.Unicode.GetBytes(str1));
            var sha512ForStr2 = ComputeHashSha512(Encoding.Unicode.GetBytes(str2));
            var sha512ForStr3 = ComputeHashSha512(Encoding.Unicode.GetBytes(str3));

            Console.WriteLine($"Str:{str1}");
            Console.WriteLine($"Hash sha512:{Convert.ToBase64String(sha512ForStr1)}");

            Console.WriteLine("");
            Console.WriteLine($"Str:{str2}");
            Console.WriteLine($"Hash sha512:{Convert.ToBase64String(sha512ForStr2)}");

            Console.WriteLine("");
            Console.WriteLine($"Str:{str3}");
            Console.WriteLine($"Hash sha512:{Convert.ToBase64String(sha512ForStr3)}");

            Console.WriteLine("");
        }
    }
}
