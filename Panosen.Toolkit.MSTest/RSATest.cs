using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Xml;
using System.IO;
using System.Diagnostics;

using Microsoft.VisualStudio.TestTools.UnitTesting;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Asn1.Pkcs;

namespace Panosen.Toolkit.MSTest
{
    [TestClass]
    public class RSATest
    {
        [TestMethod]
        public void TestRSA()
        {
            using (RSACryptoServiceProvider provider = new RSACryptoServiceProvider(2048))
            {
                string rsaPublicKey = provider.ToXmlString(false);
                string rsaPrivateKey = provider.ToXmlString(true);

                byte[] plainBytes = ByteProvider.GetBytes(100000);

                var cipherBytes = Crypto.RSAEncrypt(plainBytes, rsaPublicKey);

                var plainBytes2 = Crypto.RSADecrypt(cipherBytes, rsaPrivateKey);

                var plainSHA1Expected = Hash.SHA1(plainBytes);

                var plainSHA1Actual = Hash.SHA1(plainBytes2);

                Assert.AreEqual(plainSHA1Expected, plainSHA1Actual);
            }
        }

        /// <summary>
        /// java的加密数据，用.net来解密
        /// </summary>
        [TestMethod]
        public void TestRSADecryptCrossPlatform()
        {
            string java_rsa_public_key = JavaRsaPublicKey();
            string java_rsa_private_key = JavaRsaPrivateKey();
            string java_rsa_cipher_bytes = JavaRsaCipherBytes();
            string java_rsa_plain_sha1 = JavaRsaPlainSha1();

            var rsaPrivateKey = RSAConverter.RSAPrivateKeyJava2DotNet(java_rsa_private_key);

            byte[] cipherBytes = Convert.FromBase64String(java_rsa_cipher_bytes);

            var plainBytes = Crypto.RSADecrypt(cipherBytes, rsaPrivateKey);

            var plainSHA1Actual = Hash.SHA1(plainBytes);

            Assert.AreEqual(java_rsa_plain_sha1, plainSHA1Actual);
        }

        /// <summary>
        /// 生成测试数据给java用
        /// </summary>
        [TestMethod]
        public void GenerateDataForJava()
        {
            using (RSACryptoServiceProvider provider = new RSACryptoServiceProvider(2048))
            {
                string rsaPublicKey = provider.ToXmlString(false);
                string rsaPrivateKey = provider.ToXmlString(true);

                var javaRSAPublicKey = RSAConverter.RSAPublicKeyDotNet2Java(rsaPublicKey);
                var javaRSAPrivateKey = RSAConverter.RSAPrivateKeyDotNet2Java(rsaPrivateKey);

                var plainBytes = ByteProvider.GetBytes(10000);
                var plainBytesSHA1 = Hash.SHA1(plainBytes);

                var cipherBytes = Crypto.RSAEncrypt(plainBytes, rsaPublicKey);
                var cipherBase64 = Convert.ToBase64String(cipherBytes);

                Console.WriteLine("===RSA Public Key=======");
                Console.WriteLine(javaRSAPublicKey);

                Console.WriteLine("===RSA Private Key=======");
                Console.WriteLine(javaRSAPrivateKey);

                Console.WriteLine("===Cipher Bytes Base64=======");
                Console.WriteLine(cipherBase64);

                Console.WriteLine("===Plain Text SHA1=======");
                Console.WriteLine(plainBytesSHA1);
            }
        }

        private string JavaRsaCipherBytes()
        {
            return @"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
+WNh0iqaZDQ=";
        }

        private string JavaRsaPlainSha1()
        {
            return @"E59E91CFBE7AAEC37AE5A0945611EDA3B57AE951";
        }

        private string JavaRsaPrivateKey()
        {
            return @"MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQC8BX/OtdY0PQJDKK75xBlHhhWY
H0rJ5EyqbabixHJi43KOlQL1RPhvIFvmfILTB+ReqCVEPPy0qCcgbP20e3J2lrN4cpkZgIz3mrNV
fiWq7uQWuGJViIzrG+UAEhE+r81VZhPRkNDpvxraqqEX6meF17SQeqe95rXjyHSgKVGl5xUUXOdG
WNj1XkWc2fUVfroNhc0XzCISsn+jTsM8SUh4rFWqXXYkcxhajfrD+5t1r066lGAit6KRWFP0mgO+
+iVmwcg1x/yunDIjTP2eTZnQWvJ3nuKe21FrTKs0BxmpRq7AoI8bUyXnUlxmUAUZgnegrwzleKGs
txu6mmkFr7D5AgMBAAECggEBAJUyN+yrVcI19ymbit0ewoCC4XfIvOvfgQZr5FVlVO8rVKfXjnVZ
uVlU8BfBDX6vcIO8IXY4fr5MAGA2nEsu+fEoPFmDdgFKhJGl7FAWvYUZ81wkC8Obi1a0185qh8ya
a/EsAuX0aBJTVtfVNedoVaVbOSi8a4bBH+wUEJdWsjdV+wzhCXAdbF9p4RAfc07hnTJm4GaftNDi
+YpWGp0Icyze2yba0t3pl43mDLAozm7VoZ3oehq3td8PYvl6Jj7xBk1aX3h7Vj1pdhS5P47s8yPT
g+nt59I6u4kykatB1sR6FxWANJ+wb+wJEb9Jcpk0ug+VChznKU2oWSwPu0GvBhECgYEA/X4hIBzy
HKGuaC1Cxj5W+k2f0s0HNYIFoydz4ByvzxAI0OVYPbErKuQT0r390Y/o/p/Zt7JYKtO2UTG5si67
5PIie9ckCJii131bJTv3VF8KynQ8RrVJjHuuPKdakPpgFXGdi/kzQcpyRDReb1+Pa1EmJ1GVq30P
x5D98OkQSCsCgYEAveGW+W041YHe2EloV2RaeNzX7KOS/bF2IOwsTc/5fEv6iDoNgHnByWRLb+JI
2110ecrGMltzzjB7qa0DkQWBZCm3FKuJ8r5AxmzEFRwT5zLcTAVEPLn21VvFITwF3G+6fl+na365
o4FGGo5lW4Hfk9dEj7dc9HgRd8f61LDiFWsCgYEA7j3OsDnEKriiC/MN4PfSEylFXn+nmNh8p9x6
gVU0vqzZPEtwZXrPkV4Oa3B4zq4sUrK1knohdw7HOQQ8/IQDv6b6Vd3bVeDumwyLzzDOwRMaNzCL
PgFAALJ1DThUXBGUoFLJuTYawGiegA+f+ZicWEZKT4XT3vqJDAzvPa4tyUUCgYEAs+ciEM6QE5JJ
nejnKC3Xnj23guh0I1NZFdZOH6dVvJOMGjfOhRRXK8WPx8DAwL5p1d7uK9YEAa5j7B4Vi/iIYGs5
oCbqu4fQfW+d1FZW8S16FbjDrzmOiRW6z0M8Vl+xdXyRdkKKBkU8M3sIw0toln1V40ialLGR80gQ
+iVg/2MCgYB0oAxhhPVEiBDO1NAuTDgbNg3f+4BKe0GgFut5AAaWcECPNwghP1+LI3bwVl8G2mvj
mzUo1MVQCPOnRHwBLWpZAyI7gDs0No6iZ+H69KEjL46zy98Zd28Gg3iYkC42dGHhNjQkiTAxOFl7
hT3zFNxAn/lG0iyC5rnjoAQYPUTu6A==";
        }

        private string JavaRsaPublicKey()
        {
            return @"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvAV/zrXWND0CQyiu+cQZR4YVmB9KyeRM
qm2m4sRyYuNyjpUC9UT4byBb5nyC0wfkXqglRDz8tKgnIGz9tHtydpazeHKZGYCM95qzVX4lqu7k
FrhiVYiM6xvlABIRPq/NVWYT0ZDQ6b8a2qqhF+pnhde0kHqnvea148h0oClRpecVFFznRljY9V5F
nNn1FX66DYXNF8wiErJ/o07DPElIeKxVql12JHMYWo36w/ubda9OupRgIreikVhT9JoDvvolZsHI
Ncf8rpwyI0z9nk2Z0Fryd57inttRa0yrNAcZqUauwKCPG1Ml51JcZlAFGYJ3oK8M5XihrLcbuppp
Ba+w+QIDAQAB";
        }
    }

    /// <summary>
    /// RSA密钥格式转换
    /// </summary>
    public static class RSAConverter
    {
        /// <summary>
        /// RSA私钥格式转换，java->.net
        /// </summary>
        /// <param name="privateKey">java生成的RSA私钥</param>
        /// <returns></returns>
        public static string RSAPrivateKeyJava2DotNet(string privateKey)
        {
            RsaPrivateCrtKeyParameters privateKeyParam = (RsaPrivateCrtKeyParameters)PrivateKeyFactory.CreateKey(Convert.FromBase64String(privateKey));
            return string.Format("<RSAKeyValue><Modulus>{0}</Modulus><Exponent>{1}</Exponent><P>{2}</P><Q>{3}</Q><DP>{4}</DP><DQ>{5}</DQ><InverseQ>{6}</InverseQ><D>{7}</D></RSAKeyValue>",
            Convert.ToBase64String(privateKeyParam.Modulus.ToByteArrayUnsigned()),
            Convert.ToBase64String(privateKeyParam.PublicExponent.ToByteArrayUnsigned()),
            Convert.ToBase64String(privateKeyParam.P.ToByteArrayUnsigned()),
            Convert.ToBase64String(privateKeyParam.Q.ToByteArrayUnsigned()),
            Convert.ToBase64String(privateKeyParam.DP.ToByteArrayUnsigned()),
            Convert.ToBase64String(privateKeyParam.DQ.ToByteArrayUnsigned()),
            Convert.ToBase64String(privateKeyParam.QInv.ToByteArrayUnsigned()),
            Convert.ToBase64String(privateKeyParam.Exponent.ToByteArrayUnsigned()));
        }

        /// <summary>
        /// RSA私钥格式转换，.net->java
        /// </summary>
        /// <param name="privateKey">.net生成的私钥</param>
        /// <returns></returns>
        public static string RSAPrivateKeyDotNet2Java(string privateKey)
        {
            XmlDocument doc = new XmlDocument();
            doc.LoadXml(privateKey);
            BigInteger m = new BigInteger(1, Convert.FromBase64String(doc.DocumentElement.GetElementsByTagName("Modulus")[0].InnerText));
            BigInteger exp = new BigInteger(1, Convert.FromBase64String(doc.DocumentElement.GetElementsByTagName("Exponent")[0].InnerText));
            BigInteger d = new BigInteger(1, Convert.FromBase64String(doc.DocumentElement.GetElementsByTagName("D")[0].InnerText));
            BigInteger p = new BigInteger(1, Convert.FromBase64String(doc.DocumentElement.GetElementsByTagName("P")[0].InnerText));
            BigInteger q = new BigInteger(1, Convert.FromBase64String(doc.DocumentElement.GetElementsByTagName("Q")[0].InnerText));
            BigInteger dp = new BigInteger(1, Convert.FromBase64String(doc.DocumentElement.GetElementsByTagName("DP")[0].InnerText));
            BigInteger dq = new BigInteger(1, Convert.FromBase64String(doc.DocumentElement.GetElementsByTagName("DQ")[0].InnerText));
            BigInteger qinv = new BigInteger(1, Convert.FromBase64String(doc.DocumentElement.GetElementsByTagName("InverseQ")[0].InnerText));
            RsaPrivateCrtKeyParameters privateKeyParam = new RsaPrivateCrtKeyParameters(m, exp, d, p, q, dp, dq, qinv);
            PrivateKeyInfo privateKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(privateKeyParam);
            byte[] serializedPrivateBytes = privateKeyInfo.ToAsn1Object().GetEncoded();
            return Convert.ToBase64String(serializedPrivateBytes);
        }

        /// <summary>
        /// RSA公钥格式转换，java->.net
        /// </summary>
        /// <param name="publicKey">java生成的公钥</param>
        /// <returns></returns>
        public static string RSAPublicKeyJava2DotNet(string publicKey)
        {
            RsaKeyParameters publicKeyParam = (RsaKeyParameters)PublicKeyFactory.CreateKey(Convert.FromBase64String(publicKey));
            return string.Format("<RSAKeyValue><Modulus>{0}</Modulus><Exponent>{1}</Exponent></RSAKeyValue>",
                Convert.ToBase64String(publicKeyParam.Modulus.ToByteArrayUnsigned()),
                Convert.ToBase64String(publicKeyParam.Exponent.ToByteArrayUnsigned()));
        }

        /// <summary>
        /// RSA公钥格式转换，.net->java
        /// </summary>
        /// <param name="publicKey">.net生成的公钥</param>
        /// <returns></returns>
        public static string RSAPublicKeyDotNet2Java(string publicKey)
        {
            XmlDocument doc = new XmlDocument(); doc.LoadXml(publicKey);
            BigInteger m = new BigInteger(1, Convert.FromBase64String(doc.DocumentElement.GetElementsByTagName("Modulus")[0].InnerText));
            BigInteger p = new BigInteger(1, Convert.FromBase64String(doc.DocumentElement.GetElementsByTagName("Exponent")[0].InnerText));
            RsaKeyParameters pub = new RsaKeyParameters(false, m, p);
            SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(pub);
            byte[] serializedPublicBytes = publicKeyInfo.ToAsn1Object().GetDerEncoded();
            return Convert.ToBase64String(serializedPublicBytes);
        }
    }
}
