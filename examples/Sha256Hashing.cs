using System;
using System.Collections.Generic;
using Hashing;

namespace Sha256 {
    class Program {
        static void Main(string[] args) {
            Sha256 sha256 = new Sha256();
            sha256.Sha256Hashing();
        }
    }

    sealed class Sha256 {
        public Sha256() { }

        public void Sha256Hashing() {
            
            Hasher hasher = new Hasher();
            Salt salt = new Salt();

            string plainText = Console.ReadLine();
            KeyValuePair<byte[], string> hashProperties = hasher.ComputeHashSha256(plainText, salt.Generate(8, 16));

            string plainTextToCompare = Console.ReadLine();
            if (hasher.ValidateSha256(plainTextToCompare, hashProperties))
                Console.WriteLine("Valid! Plain text & hash are equal...");
            else
                throw new Exception("INVALID! Plain text & hash are not identical...");
        }
    }
}