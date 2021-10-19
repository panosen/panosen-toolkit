using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Text;

namespace Panosen.Toolkit.MSTest
{
    [TestClass]
    public class HashTest
    {
        private const string input = "this is a test.";

        static HashTest()
        {
            //install-package System.Text.Encoding.CodePages
            //Ö§³ÖGB2312
            Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
        }

        [TestMethod]
        public void TestMD5_1()
        {
            string actual = Hash.MD5(input);

            string expected = "09CBA091DF696AF91549DE27B8E7D0F6";

            Assert.AreEqual(expected, actual);
        }

        [TestMethod]
        public void TestMD5_2()
        {
            string actual = Hash.MD5(input, Encoding.ASCII);

            string expected = "09CBA091DF696AF91549DE27B8E7D0F6";

            Assert.AreEqual(expected, actual);
        }

        [TestMethod]
        public void TestMD5_3()
        {
            string actual = Hash.MD5(input, Encoding.GetEncoding("GB2312"));

            string expected = "09CBA091DF696AF91549DE27B8E7D0F6";

            Assert.AreEqual(expected, actual);
        }

        [TestMethod]
        public void TestSHA1_1()
        {
            string actual = Hash.SHA1(input);

            string expected = "7728F8EB7BF75EC3CC49364861EEC852FC814870";

            Assert.AreEqual(expected, actual);
        }

        [TestMethod]
        public void TestSHA1_2()
        {
            string actual = Hash.SHA1(input, Encoding.ASCII);

            string expected = "7728F8EB7BF75EC3CC49364861EEC852FC814870";

            Assert.AreEqual(expected, actual);
        }

        [TestMethod]
        public void TestSHA1_3()
        {
            string actual = Hash.SHA1(input, Encoding.GetEncoding("GB2312"));

            string expected = "7728F8EB7BF75EC3CC49364861EEC852FC814870";

            Assert.AreEqual(expected, actual);
        }

        [TestMethod]
        public void TestMethod1()
        {
            var actual = Hash.SHA256HEX("this is a test.");

            var expected = "AAAE6F4E850E064EE0CBCE6AC8FC6CAB0A17F0CE112AAEDBA122FBC782D8251B";

            Assert.AreEqual(expected, actual);
        }
    }
}
