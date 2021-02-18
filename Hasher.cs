using System;
using System.Text;
using System.Security.Cryptography;

namespace Hashing {
    public sealed class Hasher {
        public Hasher() {

        }

        public string ComputeHashSha256(string plainText, byte[] salt = null) {
            int minSaltLength = 4;
            int maxSaltLength = 16;

            byte[] saltBytes = null;

            if (!(salt is null))
                saltBytes = salt;
            else {
                Random rand = new Random();
                int len = rand.Next(minSaltLength, maxSaltLength);
                saltBytes = new byte[len];
                using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
                    rng.GetNonZeroBytes(saltBytes);
            }
            byte[] plainData = ASCIIEncoding.UTF8.GetBytes(plainText);
            int plainLength = plainData.Length;
            int saltLength = saltBytes.Length;
            byte[] plainDataAndSalt = new byte[plainLength + saltLength];

            Array.Copy(plainData, 0, plainDataAndSalt, 0, plainLength);
            Array.Copy(saltBytes, 0, plainDataAndSalt, plainLength, saltLength);

            byte[] hashvalue = null;

            using (SHA256Managed sha2 = new SHA256Managed())
                hashvalue = sha2.ComputeHash(plainDataAndSalt);

            int hashLength = hashvalue.Length;
            byte[] result = new byte[hashLength + saltLength];
            Array.Copy(hashvalue, 0, result, 0, hashLength);
            Array.Copy(saltBytes, 0, result, hashLength, saltLength);

            return ASCIIEncoding.UTF8.GetString(result);
        }

        public string ComputeHashSha512(string plainText, byte[] salt = null) {

        }

        public string ComputeHashRipemd320(string plainText) {

        }
    }
}