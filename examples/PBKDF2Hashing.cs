using System;
using System.Collections.Generic;
using Hashing;

namespace PBKDF2 {
    class Program {
        static void Main(string[] args) {
            PBKDF2 pbkdf2 = new PBKDF2();
            pbkdf2.PBKDF2Hashing();
        }
    }

    sealed class PBKDF2 {
        public PBKDF2() { }

        public void PBKDF2Hashing() {

            Console.WriteLine("The PBKDF2 example - Made By Mathijs Hoving.");
            Console.WriteLine("The GIT repository: https://github.com/mHvNG/Hasher");
            Console.WriteLine("-----------------------------------");

            Hasher hasher = new Hasher();
            Salt salt = new Salt();

            Console.WriteLine("Create your password:");
            string plainText = Console.ReadLine();
            Hasher.EncodedPBKDF2 hashProperties = hasher.ComputeHashPBKDF2(plainText, salt.Generate(24, 32), 100000);

            Console.WriteLine("-----------------------------------");
            Console.WriteLine("Enter your password:");
            string plainTextToCompare = Console.ReadLine();
            Console.WriteLine("-----------------------------------");
            if (hasher.ValidatePBKDF2(plainTextToCompare, hashProperties))
                Console.WriteLine("Valid! Plain text & hash are equal...");
            else
                throw new Exception("INVALID! Plain text & hash are not identical...");
        }
    }
}