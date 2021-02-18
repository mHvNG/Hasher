using System;
using System.Text;
using System.Security.Cryptography;

namespace Hashing {
    class Program {
        static void Main(string[] args) {
            Console.WriteLine("A hashing algorithm for C# made by Mathijs Hoving...");
            Console.WriteLine("Starting");
            Hasher hasher = new Hasher();
            string unHashedPassword = "password";
            string hashedPassword = hasher.ComputeHashSha256(unHashedPassword, new byte[12]);
            string hashedPassword2 = hasher.ComputeHashSha256("passd", new byte[12]);
            if (hashedPassword == hashedPassword2)
                Console.WriteLine("Match...");
        }
    }
}