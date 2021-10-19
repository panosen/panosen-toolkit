using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Panosen.Toolkit.MSTest
{
    internal static class ByteProvider
    {
        public static byte[] GetBytes(int count)
        {
            Random random = new Random();

            byte[] bytes = new byte[count];

            random.NextBytes(bytes);

            return bytes;
        }
    }
}
