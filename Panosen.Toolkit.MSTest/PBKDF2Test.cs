using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Panosen.Toolkit.MSTest
{
    [TestClass]
    public class PBKDF2Test
    {
        [TestMethod]
        public void Run()
        {
            var password = "zhang123";

            var cipherPassword = Crypto.PBKDF2DeriveKey(password);

            Assert.AreEqual(true, Crypto.PBKDF2Verify(password, cipherPassword));
        }
    }
}
