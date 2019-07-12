using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Drupass
{
    public class DrupalPassword
    {
        public static int MaxHashLength = 55;
        private const string Itoa64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        private const int MinHashIterations = 7;
        private const int MaxHashIterations = 30;

        public static bool CheckPassword(string password, string storedHash)
        {
            if (storedHash.Substring(0, 2) == "U$")
            {
                // storedHash begins with 'U$', and is therefore an old md5 password
                storedHash = storedHash.Substring(1);
                password = CalculateMd5Hash(password);
            }

            var type = storedHash.Substring(0, 3);
            string hash;
            switch (type)
            {
                case "$S$":
                    // storedHash begins with $S$ and is therefore sha512 encrypted
                    hash = Crypt("sha512", password, storedHash);
                    break;
                case "$H$":
                case "$P$":
                    // storedHash begins with $P$ or $H$ and is therefore md5 encrypted
                    hash = Crypt("md5", password, storedHash);
                    break;
                default:
                    throw new Exception("Unknown or ancient password format");
            }

            return hash != null && storedHash == hash;
        }

        private static string CalculateMd5Hash(string input)
        {
            // created a hex md5 hash of input string
            var algo = SHA512.Create();
            var inputBytes = Encoding.ASCII.GetBytes(input);
            var hashBytes = algo.ComputeHash(inputBytes);
            var sb = new StringBuilder();
            foreach (var t in hashBytes)
            {
                sb.Append(t.ToString("X2"));
            }
            return sb.ToString();
        }

        private static int GetCountLog2(string setting)
        {
            return Itoa64.IndexOf(setting[3]);
        }

        private static string Crypt(string algorithm, string password, string setting)
        {
            // Prevent DoS attacks by refusing to hash large passwords.
            if (password.Length > 512)
            {
                throw new Exception("Password is too long");
            }

            // The first 12 characters of an existing hash are its setting string.
            setting = setting.Substring(0, 12);
            if (setting[0] != '$' || setting[2] != '$')
            {
                throw new Exception("Setting string format is wrong (missing $ at 0 or 2)");
            }

            var countLog2 = GetCountLog2(setting);

            if (countLog2 < MinHashIterations || countLog2 > MaxHashIterations)
            {
                throw new Exception("HashIterations must be between [{MinHashIterations}] and [{MaxHashIterations}], value was [{countLog2}]");
            }

            // Hashes may be imported from elsewhere, so we allow != DRUPAL_HASH_COUNT
            var salt = setting.Substring(4, 8);

            // Hashes must have an 8 character salt.
            if (salt.Length != 8)
            {
                throw new Exception("Salt is not the correct length");
            }

            // Convert the base 2 logarithm into an integer.
            var count = 1 << countLog2;


            HashAlgorithm algo;
            switch (algorithm)
            {
                case "sha512":
                    algo = SHA512.Create();
                    break;
                case "md5":
                    algo = MD5.Create();
                    break;
                default:
                    throw new Exception($"Unknown hash algorithm [{algorithm}]");
            }

            // initial hash
            var hash = algo.ComputeHash(Encoding.ASCII.GetBytes(salt + password));

            var passwordBytes = Encoding.ASCII.GetBytes(password);

            do
            {
                var saltedPassword = new byte[hash.Length + passwordBytes.Length];
                Buffer.BlockCopy(hash, 0, saltedPassword, 0, hash.Length);
                Buffer.BlockCopy(passwordBytes, 0, saltedPassword, hash.Length, passwordBytes.Length);
                hash = algo.ComputeHash(saltedPassword);
            } while (--count > 0);

            var len = hash.Length;
            var output = setting + Base64Encode(hash);

            var expected = (int) (12 + Math.Ceiling(8f * len / 6f));
            if (output.Length != expected)
            {
                throw new Exception($"Expected an output length of [{expected}] but got [{output.Length}]");
            }

            if (output.Length <= MaxHashLength) return output;

            output = output.Substring(0, MaxHashLength);

            return output;
        }

        private static string Base64Encode(IReadOnlyList<byte> input)
        {
            var count = input.Count;
            var output = "";
            var i = 0;
            do {
                var value = (int)input[i++];
                output += Itoa64[value & 0x3f];
                if (i < count) {
                    value |= input[i] << 8;
                }
                output += Itoa64[value >> 6 & 0x3f];
                if (i++ >= count) {
                    break;
                }
                if (i < count) {
                    value |= input[i] << 16;
                }
                output += Itoa64[value >> 12 & 0x3f];
                if (i++ >= count) {
                    break;
                }
                output += Itoa64[value >> 18 & 0x3f];
            } while (i < count);
            return output;
        }
    }
}
