using System;
using System.Collections.Generic;
using Hashing;

/// <summary>
/// This namespace is not made for using like this, just to show how the Hashing library works.
/// </summary>
namespace Sha512 {
    class Program {
        static void Main(string[] args) {
            Sha512 sha512 = new Sha512();
            sha512.Sha512Hashing();
        }
    }


    sealed class Sha512 {
        public Sha512() { }
        
        /// <summary>
        /// An example of how to use the Hashing library.
        /// Within this method it creates a Salt instance, this is 100% optional. When no value is given the
        /// ComputeHashSha512 creates one itself.
        /// </summary>
        public void Sha512Hashing() {

            Console.WriteLine("The Sha512 example - Made By Mathijs Hoving.");
            Console.WriteLine("The GIT repository: https://github.com/mHvNG/Hasher");
            Console.WriteLine("-----------------------------------");

            Hasher hasher = new Hasher();
            Salt salt = new Salt();

            Console.WriteLine("Create your password:");
            string plainText = Console.ReadLine();
            KeyValuePair<byte[], string> hashProperties = hasher.ComputeHashSha512(plainText, salt.Generate(16, 32));

            Console.WriteLine("-----------------------------------");
            Console.WriteLine("Enter your password:");
            string plainTextToCompare = Console.ReadLine();
            Console.WriteLine("-----------------------------------");
            if (hasher.ValidateSha512(plainTextToCompare, hashProperties))
                Console.WriteLine("Valid! Plain text & hash are equal...");
            else
                throw new Exception("INVALID! Plain text & hash are not identical...");
        }
    }
}