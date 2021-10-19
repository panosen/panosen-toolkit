using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Panosen.Toolkit
{
    public static class Crypto
    {
        #region DES

        /// <summary>
        /// DES加密
        /// </summary>
        /// <param name="content">待加密的字符串</param>
        /// <param name="rgbIV">密钥向量，长度为8</param>
        /// <param name="rgbKey">密钥，用于加密解密，长度为8</param>
        /// <returns>返回加密内容</returns>
        /// <exception cref="System.ArgumentNullException">content为null或空</exception>
        public static byte[] DESEncode(byte[] content, byte[] rgbIV, byte[] rgbKey)
        {
            if (content == null)
            {
                throw new ArgumentNullException(nameof(content));
            }

            using (MemoryStream mStream = new MemoryStream())
            {
                DESCryptoServiceProvider provider = new DESCryptoServiceProvider();

                CryptoStream cStream = new CryptoStream(mStream, provider.CreateEncryptor(rgbKey, rgbIV), CryptoStreamMode.Write);

                cStream.Write(content, 0, content.Length);

                cStream.FlushFinalBlock();

                return mStream.ToArray();
            }
        }

        /// <summary>
        /// DES解密字符串
        /// </summary>
        /// <param name="value">待解密的字符串</param>
        /// <param name="rgbIV">密钥向量，长度为8</param>
        /// <param name="rgbKey">密钥，用于加密解密，长度为8</param>
        /// <param name="encoding">编码</param>
        /// <returns>返回解密内容</returns>
        /// <exception cref="System.ArgumentNullException">content为null或空</exception>
        public static byte[] DESDecode(byte[] value, byte[] rgbIV, byte[] rgbKey)
        {
            if (value == null)
            {
                throw new ArgumentNullException(nameof(value));
            }

            using (MemoryStream mSream = new MemoryStream())
            {
                DESCryptoServiceProvider provider = new DESCryptoServiceProvider();

                CryptoStream cStream = new CryptoStream(mSream, provider.CreateDecryptor(rgbKey, rgbIV), CryptoStreamMode.Write);

                cStream.Write(value, 0, value.Length);

                cStream.FlushFinalBlock();

                return mSream.ToArray();
            }
        }

        #endregion

        #region RSA

        /// <summary>
        /// 使用RSA加密
        /// </summary>
        /// <param name="plainBytes"></param>
        /// <param name="rsaPublicKey"></param>
        /// <returns></returns>
        public static byte[] RSAEncrypt(byte[] plainBytes, string rsaPublicKey)
        {
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            rsa.FromXmlString(rsaPublicKey);

            MemoryStream plainStream = new MemoryStream();
            MemoryStream cipherStream = new MemoryStream();

            try
            {
                plainStream = new MemoryStream(plainBytes);

                var bufferSize = rsa.KeySize / 8 - 11;
                byte[] plainBufferBytes = new byte[bufferSize];

                int plainCount = plainStream.Read(plainBufferBytes, 0, bufferSize);
                while (plainCount > 0)
                {
                    if (plainCount < bufferSize)
                    {
                        var bytes = new byte[plainCount];

                        Array.Copy(plainBufferBytes, bytes, plainCount);

                        var cipherBytes = rsa.Encrypt(bytes, false);

                        cipherStream.Write(cipherBytes, 0, cipherBytes.Length);
                    }
                    else
                    {
                        var cipherBytes = rsa.Encrypt(plainBufferBytes, false);

                        cipherStream.Write(cipherBytes, 0, cipherBytes.Length);
                    }

                    plainCount = plainStream.Read(plainBufferBytes, 0, bufferSize);
                }

                return cipherStream.ToArray();
            }
            finally
            {
                if (rsa != null)
                {
                    rsa.Dispose();
                }
                if (plainStream != null)
                {
                    plainStream.Dispose();
                }
                if (cipherStream != null)
                {
                    cipherStream.Dispose();
                }
            }
        }

        /// <summary>
        /// 使用RSA解密
        /// </summary>
        /// <param name="cipherBytes"></param>
        /// <param name="rsaPrivateKey"></param>
        /// <returns></returns>
        public static byte[] RSADecrypt(byte[] cipherBytes, string rsaPrivateKey)
        {
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            rsa.FromXmlString(rsaPrivateKey);

            MemoryStream cipherStream = new MemoryStream(cipherBytes);
            MemoryStream plainStream = new MemoryStream();

            try
            {
                var bufferSize = rsa.KeySize / 8;
                byte[] cipherBufferBytes = new byte[bufferSize];

                int cipherCount = cipherStream.Read(cipherBufferBytes, 0, bufferSize);
                while (cipherCount > 0)
                {
                    var plainBytes = rsa.Decrypt(cipherBufferBytes, false);

                    plainStream.Write(plainBytes, 0, plainBytes.Length);

                    cipherCount = cipherStream.Read(cipherBufferBytes, 0, bufferSize);
                }

                return plainStream.ToArray();
            }
            finally
            {
                if (rsa != null)
                {
                    rsa.Dispose();
                }
                if (cipherStream != null)
                {
                    cipherStream.Dispose();
                }
                if (plainStream != null)
                {
                    plainStream.Dispose();
                }
            }
        }

        #endregion

        #region AES

        /// <summary>
        /// 使用AES加密
        /// </summary>
        /// <param name="plainBytes"></param>
        /// <param name="aesKey">长度16, 24, 32</param>
        /// <param name="aesIV">长度16</param>
        /// <returns></returns>
        public static byte[] AESEncrypt(byte[] plainBytes, byte[] aesKey, byte[] aesIV)
        {
            AesManaged aesProvider = new AesManaged();

            MemoryStream cipherStream = new MemoryStream();

            CryptoStream cryptoStream = new CryptoStream(cipherStream, aesProvider.CreateEncryptor(aesKey, aesIV), CryptoStreamMode.Write);

            try
            {
                cryptoStream.Write(plainBytes, 0, plainBytes.Length);
                cryptoStream.FlushFinalBlock();

                return cipherStream.ToArray();
            }
            finally
            {
                if (aesProvider != null)
                {
                    aesProvider.Dispose();
                }
                if (cipherStream != null)
                {
                    cipherStream.Dispose();
                }
                if (cryptoStream != null)
                {
                    cryptoStream.Dispose();
                }
            }
        }

        /// <summary>
        /// 使用AES解密
        /// </summary>
        /// <param name="cipherBytes"></param>
        /// <param name="aesKey">长度16, 24, 32</param>
        /// <param name="aesIV">长度16</param>
        /// <returns></returns>
        public static byte[] AESDecrypt(byte[] cipherBytes, byte[] aesKey, byte[] aesIV)
        {
            AesManaged aesProvider = new AesManaged();

            MemoryStream plainStream = new MemoryStream();

            CryptoStream cryptoStream = new CryptoStream(plainStream, aesProvider.CreateDecryptor(aesKey, aesIV), CryptoStreamMode.Write);

            try
            {
                cryptoStream.Write(cipherBytes, 0, cipherBytes.Length);
                cryptoStream.FlushFinalBlock();

                return plainStream.ToArray();
            }
            finally
            {
                if (aesProvider != null)
                {
                    aesProvider.Dispose();
                }
                if (cryptoStream != null)
                {
                    cryptoStream.Dispose();
                }
                if (plainStream != null)
                {
                    plainStream.Dispose();
                }
            }
        }

        #endregion

        #region PBKDF2

        /// <summary>
        /// 将密码加密
        /// </summary>
        /// <param name="password">原始密码</param>
        /// <returns>加密后的密码</returns>
        public static byte[] PBKDF2DeriveKey(string password)
        {
            byte[] salt = new byte[8];
            using (RNGCryptoServiceProvider rngCsp = new RNGCryptoServiceProvider())
            {
                // Fill the array with a random value.
                rngCsp.GetBytes(salt);
            }

            Rfc2898DeriveBytes key = new Rfc2898DeriveBytes(password, salt, 1024); //1024次迭代
            byte[] pbkdf2 = key.GetBytes(16);

            //将盐和pbkdf2值拼接后返回
            byte[] returnValue = new byte[salt.Length + pbkdf2.Length];
            Array.Copy(salt, 0, returnValue, 0, salt.Length);
            Array.Copy(pbkdf2, 0, returnValue, salt.Length, pbkdf2.Length);

            return returnValue;
        }

        /// <summary>
        /// 验证密码是否正确
        /// </summary>
        /// <param name="password">需要验证的的密码</param>
        /// <param name="pbkdf2">原始密码加密之后的密码</param>
        /// <returns></returns>
        public static bool PBKDF2Verify(string password, byte[] pbkdf2)
        {
            byte[] salt = new byte[8];
            byte[] pb = new byte[pbkdf2.Length - 8];

            Array.Copy(pbkdf2, 0, salt, 0, salt.Length);
            Array.Copy(pbkdf2, salt.Length, pb, 0, pb.Length);

            Rfc2898DeriveBytes key = new Rfc2898DeriveBytes(password, salt, 1024); //1024次迭代
            byte[] pb2 = key.GetBytes(16);

            if (pb2.Length != pb.Length)
            {
                return false;
            }

            for (int i = 0; i < pb.Length; ++i)
            {
                if (pb2[i] != pb[i])
                {
                    return false;
                }
            }

            return true;
        } 

        #endregion
    }
}
