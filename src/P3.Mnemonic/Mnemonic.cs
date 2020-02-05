using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using P3.Mnemonic.System.Security.Cryptography;

namespace P3.Mnemonic
{
    public enum WordListLanguage
    {
        ChineseSimplified,
        ChineseTraditional,
        English,
        French,
        Italian,
        Japanese,
        Korean,
        Spanish
    }

    public static class Mnemonic
    {
        private const string InvalidMnemonic = "Invalid mnemonic";
        private const string InvalidEntropy = "Invalid entropy";
        private const string InvalidChecksum = "Invalid mnemonic checksum";

        private static string LeftPad(string str, string padString, int length)
        {
            while (str.Length < length)
            {
                str = padString + str;
            }

            return str;
        }

        public static string MnemonicToEntropy(string mnemonic, WordListLanguage wordListType)
        {
            var wordList = GetWordList(wordListType);
            var words = mnemonic.Normalize(NormalizationForm.FormKD).Split(new[] { ' ' },
                StringSplitOptions.RemoveEmptyEntries);

            if (words.Length % 3 != 0)
            {
                throw new ArgumentException(InvalidMnemonic);
            }

            var bits = string.Join("", words.Select(word =>
            {
                var index = Array.IndexOf(wordList, word);
                if (index == -1)
                {
                    throw new ArgumentException(InvalidMnemonic);
                }

                return LeftPad(Convert.ToString(index, 2), "0", 11);
            }));

            // split the binary string into ENT/CS
            var dividerIndex = (int)Math.Floor((double)bits.Length / 33) * 32;
            var entropyBits = bits.Substring(0, dividerIndex);
            var checksumBits = bits.Substring(dividerIndex);

            // calculate the checksum and compare
            var entropyBytesMatch = Regex.Matches(entropyBits, "(.{1,8})")
                .OfType<Match>()
                .Select(m => m.Groups[0].Value)
                .ToArray();

            var entropyBytes = entropyBytesMatch
                .Select(bytes => Convert.ToByte(bytes, 2)).ToArray();

            CheckValidEntropy(entropyBytes);


            var newChecksum = DeriveChecksumBits(entropyBytes);

            if (newChecksum != checksumBits)
                throw new Exception(InvalidChecksum);

            var result = BitConverter
                .ToString(entropyBytes)
                .Replace("-", "")
                .ToLower();

            return result;
        }

        public static string EntropyToMnemonic(string entropy, WordListLanguage wordListType)
        {
            var wordList = GetWordList(wordListType);

            //How can I do this more efficiently, the multiple substrings I don't like...
            var entropyBytes = Enumerable.Range(0, entropy.Length / 2)
                .Select(x => Convert.ToByte(entropy.Substring(x * 2, 2), 16))
                .ToArray();

            CheckValidEntropy(entropyBytes);

            var entropyBits = BytesToBinary(entropyBytes);
            var checksumBits = DeriveChecksumBits(entropyBytes);

            var bits = entropyBits + checksumBits;

            var chunks = Regex.Matches(bits, "(.{1,11})")
                .OfType<Match>()
                .Select(m => m.Groups[0].Value)
                .ToArray();

            var words = chunks.Select(binary =>
                {
                    var index = Convert.ToInt32(binary, 2);
                    return wordList[index];
                });

            var joinedText = String.Join((wordListType == WordListLanguage.Japanese ? "\u3000" : " "), words);

            return joinedText;
        }

        public static string GenerateMnemonic(int strength, WordListLanguage wordListType)
        {
            if (strength % 32 != 0)
                throw new NotSupportedException(InvalidEntropy);

            RNGCryptoServiceProvider rngCryptoServiceProvider = new RNGCryptoServiceProvider();

            byte[] buffer = new byte[strength / 8];
            rngCryptoServiceProvider.GetBytes(buffer);

            var entropyHex = BitConverter.ToString(buffer).Replace("-", "");

            return EntropyToMnemonic(entropyHex, wordListType);
        }

        private static void CheckValidEntropy(byte[] entropyBytes)
        {
            if (entropyBytes == null) 
                throw new ArgumentNullException(nameof(entropyBytes));
            
            if (entropyBytes.Length < 16)
                throw new ArgumentException(InvalidEntropy);

            if (entropyBytes.Length > 32)
                throw new ArgumentException(InvalidEntropy);

            if (entropyBytes.Length % 4 != 0)
                throw new ArgumentException(InvalidEntropy);
        }

        private static string Salt(string password)
        {
            return "mnemonic" + (!string.IsNullOrEmpty(password) ? password : "");
        }

        private static byte[] MnemonicToSeed(string mnemonic, string password)
        {
            var mnemonicBytes = Encoding.UTF8.GetBytes(mnemonic.Normalize(NormalizationForm.FormKD));
            var saltBytes = Encoding.UTF8.GetBytes(Salt(password.Normalize(NormalizationForm.FormKD)));

            var rfc2898DerivedBytes = new Rfc2898DeriveBytesExtended(mnemonicBytes, saltBytes, 2048, HashAlgorithmName.SHA512);
            var key = rfc2898DerivedBytes.GetBytes(64);

            return key;
        }

        public static string MnemonicToSeedHex(string mnemonic, string password)
        {
            var key = MnemonicToSeed(mnemonic, password);
            var hex = BitConverter
                .ToString(key)
                .Replace("-", "")
                .ToLower();

            return hex;
        }

        private static string DeriveChecksumBits(byte[] checksum)
        {
            var ent = checksum.Length * 8;
            var cs = ent / 32;

            var sha256Provider = new SHA256CryptoServiceProvider();
            var hash = sha256Provider.ComputeHash(checksum);
            string result = BytesToBinary(hash);
            return result.Substring(0, cs);
        }

        private static string BytesToBinary(byte[] hash)
        {
            return string.Join("", hash.Select(h => LeftPad(Convert.ToString(h, 2), "0", 8)));
        }

        public static bool ValidateMnemonic(string mnemonic, WordListLanguage wordList)
        {
            try
            {
                MnemonicToEntropy(mnemonic, wordList);
            }
            catch
            {
                return false;
            }
            return true;
        }

        private static string[] GetWordList(WordListLanguage wordList)
        {
            var wordLists = new Dictionary<string, string>
            {
                {WordListLanguage.ChineseSimplified.ToString(), "chinese_simplified"},
                {WordListLanguage.ChineseTraditional.ToString(), "chinese_traditional"},
                {WordListLanguage.English.ToString(), "english"},
                {WordListLanguage.French.ToString(), "french"},
                {WordListLanguage.Italian.ToString(), "italian"},
                {WordListLanguage.Japanese.ToString(), "japanese"},
                {WordListLanguage.Korean.ToString(), "korean"},
                {WordListLanguage.Spanish.ToString(), "spanish"}
            };

            var wordListFile = wordLists[wordList.ToString()];

            var wordListFileStream = Assembly.GetAssembly(typeof(WordListLanguage))
                .GetManifestResourceStream($"{typeof(WordListLanguage).Namespace}.Words.{wordListFile}.txt");

            var words = new List<string>();
            using (StreamReader reader = new StreamReader(wordListFileStream ?? throw new InvalidOperationException($"could not load word list for {wordList}")))
            {
                while (reader.Peek() >= 0)
                {
                    words.Add(reader.ReadLine());
                }
            }

            var wordListResults = words.ToArray();
            return wordListResults;
        }

    }
}