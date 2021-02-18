using System;

namespace Hashing {
    class Program {
        static void Main(string[] args) {
            Console.WriteLine("A hashing algorithm for C# made by Mathijs Hoving...");
            Console.WriteLine("Starting");
            Hasher hasher = new Hasher();
            string unHashedPassword = "password";
            string hashedPassword = hasher.ComputeHashSha256("password");
            Console.WriteLine($"Password Hashing Complete... Given password: {unHashedPassword} ::: Hashed password: {hashedPassword};");
        }
    }
}