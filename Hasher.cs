using System;
using System.Text;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace Hashing {

    public sealed class Salt {
        public Salt() { }

        public byte[] Generate(int minSaltLength, int maxSaltLength) {
            byte[] saltBytes = null;
            
            Random rand = new Random();
            int len = rand.Next(minSaltLength, maxSaltLength);

            saltBytes = new byte[len];
            using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
                rng.GetNonZeroBytes(saltBytes);

            return saltBytes;
        }
    }

    public sealed class Hasher {

        private enum Types {
            Sha256,
            Sha512
        }

        public struct EncodedPBKDF2 {
            public byte[] Hash { get; set; }
            public byte[] Salt { get; set; }
            public int Iterations { get; set; }
        }

        public Hasher() {
            
        }

        public KeyValuePair<byte[], string> ComputeHashSha256(string plainText, byte[] salt = null) { return this.ComputeHashSha((int)Types.Sha256, plainText, salt); }

        public KeyValuePair<byte[], string> ComputeHashSha512(string plainText, byte[] salt = null) { return this.ComputeHashSha((int)Types.Sha512, plainText, salt); }

        public bool ValidateSha256(string plainText, KeyValuePair<byte[], string> hashedResult) { return this.Validate((int)Types.Sha256, plainText, hashedResult); }

        public bool ValidateSha512(string plainText, KeyValuePair<byte[], string> hashedResult) { return this.Validate((int)Types.Sha512, plainText, hashedResult); }

        public EncodedPBKDF2 ComputeHashPBKDF2(string plainText, byte[] salt = null, long iterations = 100000) {

            const int minSaltLength = 24;
            const int maxSaltLength = 32;

            byte[] saltBytes = null;

            if (Encoding.UTF8.GetString(salt) == Encoding.UTF8.GetString(new byte[salt.Length]))
                throw new Exception("A generic byte value was given... It requires a random generated salt value! Try the method `Generate` within the class Salt or let the mothod create one.");

            if (!(salt is null))
                saltBytes = salt;
            else {
                Salt saltGenerator = new Salt();
                saltBytes = saltGenerator.Generate(minSaltLength, maxSaltLength);
            }

            byte[] hashCode = null;

            using (Rfc2898DeriveBytes hash = new Rfc2898DeriveBytes(plainText, saltBytes, (int)iterations))
                hashCode = hash.GetBytes(saltBytes.Length);

            EncodedPBKDF2 encodedHash = default(EncodedPBKDF2);
            encodedHash.Hash = hashCode;
            encodedHash.Salt = saltBytes;
            encodedHash.Iterations = (int)iterations;

            return encodedHash;
        }

        public bool ValidatePBKDF2(string plainText, EncodedPBKDF2 hash) {
            EncodedPBKDF2 newHash = this.ComputeHashPBKDF2(plainText, hash.Salt, hash.Iterations);
            if (ASCIIEncoding.UTF8.GetString(hash.Hash) != ASCIIEncoding.UTF8.GetString(newHash.Hash))
                return false;
            return true;
        }

        /**
            * * There is a option to give your own salt length.
            * ! IMPORTANT: As advice don't use the same salt length, USE your own randomizer
            * @param plainText the string as plain text
            * @param salt the length of the salt
         */
        private KeyValuePair<byte[], string> ComputeHashSha(int type, string plainText, byte[] salt = null) {

            int multiplyer = 1;
            if (type == (int)Types.Sha512)
                multiplyer = 2;

            /**
                * * A mimimum & maximum salt length. Salts must be unique, this hashing method uses the Random Class, so the salt length will use the same length occasionally.
             */
            int minSaltLength = 8*multiplyer; // 64 or 128 Bit
            int maxSaltLength = 16*multiplyer; // 128 or 256 Bit

            byte[] saltBytes = null;

            /**
                * Statement for setting up the salt length. 
                * ! When there's not a given length the method randomizes a length.
             */
            
            if (Encoding.UTF8.GetString(salt) == Encoding.UTF8.GetString(new byte[salt.Length]))
                throw new Exception("A generic byte value was given... It requires a random generated salt value! Try the method `Generate` within the class Salt or let the mothod create one.");

            if (!(salt is null))
                saltBytes = salt;
            else {
                Salt saltGenerator = new Salt();
                saltBytes = saltGenerator.Generate(minSaltLength, maxSaltLength);
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
                * Compute the combined array `plainDataAndSalt` to a hash code for the correct type
             */
            switch(type) {
                case (int)Types.Sha256:
                    using (SHA256Managed sha2 = new SHA256Managed())
                        hashCode = sha2.ComputeHash(plainDataAndSalt);
                    break;
                case (int)Types.Sha512:
                    using (SHA512Managed sha512 = new SHA512Managed())
                        hashCode = sha512.ComputeHash(plainDataAndSalt);
                    break;
            }

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

            return new KeyValuePair<byte[], string>(saltBytes, ASCIIEncoding.UTF8.GetString(result));
        }

        private bool Validate(int type, string plainText, KeyValuePair<byte[], string> hashedResult) {
            if (hashedResult.Key is null)
                throw new Exception("Argument salt cannot have value null...");
            byte[] salt = hashedResult.Key;
            string hashedString = hashedResult.Value;
            /**
                * * Hash the unhashed string
             */
            string result = "";
            switch(type) {
                case (int)Types.Sha256:
                    result = this.ComputeHashSha256(plainText, salt).Value;
                    break;
                case (int)Types.Sha512:
                    result = this.ComputeHashSha512(plainText, salt).Value;
                    break;
            }
            if (result != hashedString)
                return false;
            return true;
        }
    }
}