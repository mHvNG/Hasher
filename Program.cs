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
            string firstPassword = Console.ReadLine();
            KeyValuePair<byte[], string> hashedPassword = hasher.ComputeHashSha256(firstPassword);
            string secondPassword = Console.ReadLine();
            if (hasher.ValidateSha256(secondPassword, hashedPassword))
                Console.WriteLine("A successfull match found between the passwords...");
        }
    }
}