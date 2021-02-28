using System;
using System.Collections.Generic;

namespace Hashing {
    class Program {
        static void Main(string[] args) {
            Console.WriteLine("A hashing algorithm for C# made by Mathijs Hoving...");
            Console.WriteLine("Starting");
            Hasher hasher = new Hasher();
            Salt salt = new Salt();
            string firstPassword = Console.ReadLine();
            // KeyValuePair<byte[], string> hashedPassword = hasher.ComputeHashSha256(firstPassword, salt.Generate(8, 16));
            // string secondPassword = Console.ReadLine();
            // if (hasher.ValidateSha256(secondPassword, hashedPassword))
            //     Console.WriteLine("A successfull match found between the passwords...");
            Hasher.EncodedPBKDF2 hash = hasher.ComputeHashPBKDF2(firstPassword, salt.Generate(24, 32));
            string secondPassword = Console.ReadLine();
            if (hasher.ValidatePBKDF2(secondPassword, hash))
                Console.WriteLine("A successfull match found between the passwords...");
        }
    }
}