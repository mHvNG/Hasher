using System;
using System.Text;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace Hashing {
    class Program {
        static void Main(string[] args) {
            Console.WriteLine("A hashing algorithm for C# made by Mathijs Hoving...");
            Console.WriteLine("Starting");
            Hasher hasher = new Hasher();
            string unHashedPassword = "password";
            // string hashedPassword = hasher.ComputeHashSha256(unHashedPassword, new byte[12]);
            KeyValuePair<byte[], string> hashedPassword = hasher.ComputeHashSha256(unHashedPassword);
            Console.WriteLine($"The Salt: {Encoding.UTF8.GetString(hashedPassword.Key)}");
        }
    }
}