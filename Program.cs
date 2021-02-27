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
            Salt salt = new Salt();
            // string firstPassword = Console.ReadLine();
            // KeyValuePair<byte[], string> hashedPassword = hasher.ComputeHashSha256(firstPassword, new byte[13]);
            // string secondPassword = Console.ReadLine();
            // if (hasher.ValidateSha256(secondPassword, hashedPassword))
            //     Console.WriteLine("A successfull match found between the passwords...");
            Hasher.EncodedPBKDF2 hash = hasher.ComputeHashPBKDF2("password", salt.Generate(24, 32));
            Console.WriteLine($"Hash  :  {hash.Hash} - Salt  :  {hash.Salt.Length} - Iterations  :  {hash.Iterations.ToString()}");
        }
    }
}