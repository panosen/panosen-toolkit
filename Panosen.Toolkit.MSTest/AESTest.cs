using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Panosen.Toolkit.MSTest
{
    [TestClass]
    public class AESTest
    {
        [TestMethod]
        public void TestAES()
        {
            using (AesManaged aesProvider = new AesManaged())
            {
                aesProvider.GenerateKey();

                var key = aesProvider.Key;
                var iv = aesProvider.IV;

                byte[] plainBytes = ByteProvider.GetBytes(100000);

                var cipherBytes = Crypto.AESEncrypt(plainBytes, key, iv);

                var plainBytes2 = Crypto.AESDecrypt(cipherBytes, key, iv);

                var plainSHA1Expected = Hash.SHA1(plainBytes);

                var plainSHA1Actual = Hash.SHA1(plainBytes2);

                Assert.AreEqual(plainSHA1Expected, plainSHA1Actual);
            }
        }

        [TestMethod]
        public void TestAesEncryptCrossPlatform()
        {
            var plainText = "this jdiqidjiweidiowjeiodiowejdwuehduihwuehdueiojdiwjed wued 张三";

            var plainBytes = Encoding.UTF8.GetBytes(plainText);

            byte[] keys = new byte[] { 5, 51, 70, 45, 113, 58, 19, 70, 3, 3, 29, 65, 91, 72, 108, 57, 36, 64, 22, 120, 41, 14, 113, 83, 51, 43, 76, 9, 24, 17, 108, 127 };
            byte[] iv = new byte[] { 44, 13, 113, 65, 125, 79, 113, 2, 93, 8, 17, 85, 46, 70, 6, 118, };

            var cipherBytes = Crypto.AESEncrypt(plainBytes, keys, iv);

            var actualSHA1 = Hash.SHA1(cipherBytes);

            var expectedSHA1 = "47E61E47BFB331E474861FBA09FE4E4E14B84A6C";

            Assert.AreEqual(expectedSHA1, actualSHA1);
        }

        [TestMethod]
        public void TestAesDecryptCrossPlatform()
        {
            string cipherBase64 = "p8M3btMnH9L3zYS8qX2FrxLeg0pkOIpQ7V0/bc12tJv3ulyhO3tyDHgR1NKvsMIjNeNq9XkGcupJIs9qQVFDlw==";

            byte[] cipherBytes = Convert.FromBase64String(cipherBase64);

            byte[] keys = new byte[] { 5, 51, 70, 45, 113, 58, 19, 70, 3, 3, 29, 65, 91, 72, 108, 57, 36, 64, 22, 120, 41, 14, 113, 83, 51, 43, 76, 9, 24, 17, 108, 127 };
            byte[] iv = new byte[] { 44, 13, 113, 65, 125, 79, 113, 2, 93, 8, 17, 85, 46, 70, 6, 118, };

            byte[] plainBytes = Crypto.AESDecrypt(cipherBytes, keys, iv);

            string plainTextActual = Encoding.UTF8.GetString(plainBytes);

            string plainTextExpected = "this jdiqidjiweidiowjeioddw好ojdiwjed wued 张三";

            Assert.AreEqual(plainTextExpected, plainTextActual);
        }
    }
}
