using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Panosen.Toolkit
{
    /// <summary>
    /// 哈希
    /// </summary>
    public static class Hash
    {
        /// <summary>
        /// 将指定的字符串进行MD5加密
        /// </summary>
        /// <param name="value">要加密的字符串</param>
        /// <param name="encoding">编码</param>
        /// <returns>加密后的结果</returns>
        /// <exception cref="System.ArgumentNullException">content为null或空</exception>
        public static string MD5(string value, Encoding encoding = default)
        {
            if (string.IsNullOrEmpty(value))
            {
                throw new ArgumentNullException(nameof(value));
            }

            var bytes = (encoding ?? Encoding.UTF8).GetBytes(value);

            return MD5(bytes);
        }

        public static string MD5(byte[] bytes)
        {
            if (bytes == null || bytes.Length == 0)
            {
                throw new ArgumentNullException(nameof(bytes));
            }

            MD5CryptoServiceProvider provider = new MD5CryptoServiceProvider();

            var hash = provider.ComputeHash(bytes);

            return BitConverter.ToString(hash).Replace("-", string.Empty);
        }

        /// <summary>
        /// 使用UTF8编码获取指定字符串的SHA1值
        /// </summary>
        /// <param name="value">指定的字符串</param>
        /// <returns>sha1编码后的值</returns>
        public static string SHA1(string value)
        {
            return SHA1(value, Encoding.UTF8);
        }

        /// <summary>
        /// 使用指定编码获取指定字符串的SHA1值
        /// </summary>
        /// <param name="value">指定的字符串</param>
        /// <param name="encoding">编码</param>
        /// <returns>sha1编码后的值</returns>
        public static string SHA1(string value, Encoding encoding)
        {
            if (string.IsNullOrEmpty(value))
            {
                throw new ArgumentNullException(nameof(value));
            }

            var bytes = encoding.GetBytes(value);

            return SHA1(bytes);
        }

        /// <summary>
        /// 获取SHA1值
        /// </summary>
        /// <param name="bytes"></param>
        /// <returns></returns>
        public static string SHA1(byte[] bytes)
        {
            if (bytes == null || bytes.Length == 0)
            {
                throw new ArgumentNullException(nameof(bytes));
            }

            SHA1CryptoServiceProvider provider = new SHA1CryptoServiceProvider();

            var hash = provider.ComputeHash(bytes);

            return string.Concat(hash.Select(v => v.ToString("X2")));
        }

        /// <summary>
        /// Sha256Hex
        /// </summary>
        public static string SHA256HEX(string text, Encoding encoding = default)
        {
            var bytes = (encoding ?? Encoding.UTF8).GetBytes(text);

            return SHA256HEX(bytes);
        }

        /// <summary>
        /// Sha256Hex
        /// </summary>
        public static string SHA256HEX(byte[] bytes)
        {
            using (SHA256 sha256 = SHA256.Create())
            {
                byte[] hashbytes = sha256.ComputeHash(bytes);
                StringBuilder builder = new StringBuilder();
                for (int i = 0; i < hashbytes.Length; i++)
                {
                    builder.Append(hashbytes[i].ToString("X2"));
                }
                return builder.ToString();
            }
        }

        /// <summary>
        /// HmacSha256
        /// </summary>
        public static byte[] HMACSHA256(byte[] key, byte[] msg)
        {
            using (HMACSHA256 hMACSHA256 = new HMACSHA256(key))
            {
                return hMACSHA256.ComputeHash(msg);
            }
        }
    }
}
