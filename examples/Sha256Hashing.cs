using System;
using System.Collections.Generic;
using Hashing;

/// <summary>
/// This namespace is not made for using like this, just to show how the Hashing library works.
/// </summary>
namespace Sha256 {
    class Program {
        static void Main(string[] args) {
            Sha256 sha256 = new Sha256();
            sha256.Sha256Hashing();
        }
    }

    sealed class Sha256 {
        public Sha256() { }

        /// <summary>
        /// An example of how to use the Hashing library.
        /// Within this method it creates a Salt instance, this is 100% optional. When no value is given the
        /// ComputeHashSha256 creates one itself.
        /// </summary>
        public void Sha256Hashing() {

            Console.WriteLine("The Sha256 example - Made By Mathijs Hoving.");
            Console.WriteLine("The GIT repository: https://github.com/mHvNG/Hasher");
            Console.WriteLine("-----------------------------------");
            
            Hasher hasher = new Hasher();
            Salt salt = new Salt(); // OPTIONAL

            Console.WriteLine("Create your password:");
            string plainText = Console.ReadLine();
            KeyValuePair<byte[], string> hashProperties = hasher.ComputeHashSha256(plainText, salt.Generate(8, 16));

            Console.WriteLine("-----------------------------------");
            Console.WriteLine("Enter your password:");
            string plainTextToCompare = Console.ReadLine();
            Console.WriteLine("-----------------------------------");
            if (hasher.ValidateSha256(plainTextToCompare, hashProperties))
                Console.WriteLine("Valid! Plain text & hash are equal...");
            else
                throw new Exception("INVALID! Plain text & hash are not identical...");
        }
    }
}