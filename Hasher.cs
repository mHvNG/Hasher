using System;
using System.Text;
using System.Security.Cryptography;

namespace Hashing {
    public sealed class Hasher {
        public Hasher() {

        }

        /**
            * * There is a option to give your own salt length.
            * ! IMPORTANT: DON'T use the same salt length, USE your own randomizer
            * @param plainText the string as plain text
            * @param salt the length of the salt
         */
        public string ComputeHashSha256(string plainText, byte[] salt = null) {
            /**
                * * A mimimum & maximum salt length. Salts must be unique, this hashing method uses the Random Class, so the salt length will use the same length occasionally.
                * ! That means the method isn't the best hasher for really important data.
             */
            int minSaltLength = 8;
            int maxSaltLength = 16;

            byte[] saltBytes = null;

            /**
                * Statement for setting up the salt length. 
                * ! When there's not a given length the method randomizes a length.
                * ! IMPORTANT: As stated above the randomizer isn't flawless, it can pick the same length occasionally.
             */
            if (!(salt is null))
                saltBytes = salt;
            else {
                Random rand = new Random();
                int len = rand.Next(minSaltLength, maxSaltLength);
                saltBytes = new byte[len];
                using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
                    rng.GetNonZeroBytes(saltBytes);
            }
            
            /**
                * Initialization for copying a range of elements to `plainDataAndSalt`
             */
            byte[] plainData = ASCIIEncoding.UTF8.GetBytes(plainText);
            int plainLength = plainData.Length;
            int saltLength = saltBytes.Length;
            byte[] plainDataAndSalt = new byte[plainLength + saltLength];
            
            /**
                * Copying the byte arrays of the plainText and salt length to a combined array `plainDataAndSalt`
             */
            Array.Copy(plainData, 0, plainDataAndSalt, 0, plainLength);
            Array.Copy(saltBytes, 0, plainDataAndSalt, plainLength, saltLength);

            byte[] hashCode = null;

            /**
                * Compute the combined array `plainDataAndSalt` to a hash code
             */
            using (SHA256Managed sha2 = new SHA256Managed())
                hashCode = sha2.ComputeHash(plainDataAndSalt);

            /**
                * Initialization for copying a range of elements from the computed hashcode and salt length.
             */
            int hashLength = hashCode.Length;
            byte[] result = new byte[hashLength + saltLength];

            /**
                * Copying the byte arrays of the hash code and salt length to the end result hash value.
             */
            Array.Copy(hashCode, 0, result, 0, hashLength);
            Array.Copy(saltBytes, 0, result, hashLength, saltLength);

            return ASCIIEncoding.UTF8.GetString(result);
        }

        public string ComputeHashSha512(string plainText, byte[] salt = null) {

        }

        public string ComputeHashRipemd320(string plainText) {

        }
    }
}