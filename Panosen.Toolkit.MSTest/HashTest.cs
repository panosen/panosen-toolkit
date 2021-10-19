using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Text;

namespace Panosen.Toolkit.MSTest
{
    [TestClass]
    public class HashTest
    {
        private const string input = "this is a test 张三";

        static HashTest()
        {
            //install-package System.Text.Encoding.CodePages
            //支持GB2312
            Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
        }

        [TestMethod]
        public void TestMD5_1()
        {
            string actual = Hash.MD5(input);

            string expected = "44A53A7E04B8836DF5CE498962F1B8CC";

            Assert.AreEqual(expected, actual);
        }

        [TestMethod]
        public void TestMD5_2()
        {
            string actual = Hash.MD5(input, Encoding.ASCII);

            string expected = "600F887F1F24E4895B23CD0F1409D18D";

            Assert.AreEqual(expected, actual);
        }

        [TestMethod]
        public void TestMD5_3()
        {
            string actual = Hash.MD5(input, Encoding.GetEncoding("GB2312"));

            string expected = "2C1D6A643BD36BBBB21792295B5D34BB";

            Assert.AreEqual(expected, actual);
        }

        [TestMethod]
        public void TestSHA1_1()
        {
            string actual = Hash.SHA1(input);

            string expected = "0B9EE479E853AADD6FF660A7D347AE977874F692";

            Assert.AreEqual(expected, actual);
        }

        [TestMethod]
        public void TestSHA1_2()
        {
            string actual = Hash.SHA1(input, Encoding.ASCII);

            string expected = "39BE21C7350F4EAEA9C94D0DC688CB65028D8910";

            Assert.AreEqual(expected, actual);
        }

        [TestMethod]
        public void TestSHA1_3()
        {
            string actual = Hash.SHA1(input, Encoding.GetEncoding("GB2312"));

            string expected = "A7DBF145E5ACF69F212F36FC17A32724C58DF7E2";

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
