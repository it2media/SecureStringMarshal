using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace SecureStringMarshal
{
    public static class StringExtensions
    {
        public static SecureString FromProtectedString(this string protectedData, ref string salt)
        {
            using (StringToSecureStringMarshal saltMarshalString = new StringToSecureStringMarshal(ref salt, false))
            {
                using (SecureStringToBytesMarshal saltMarshalBytes = new SecureStringToBytesMarshal(saltMarshalString.SecureString))
                {
                    byte[] protectedByteArray = Convert.FromBase64String(protectedData);
                    byte[] decryptedData = ProtectedData.Unprotect(protectedByteArray, saltMarshalBytes.Bytes, DataProtectionScope.CurrentUser); //use UnprotectBinaryForUser for null checks

                    using (BytesToSecureStringMarshal bytesToSecureStringMarshal = new BytesToSecureStringMarshal(ref decryptedData))
                    {
                        return bytesToSecureStringMarshal.SecureString;
                    }
                }
            }
        }

        public static SecureString FromProtectedString(this string protectedData, SecureString salt)
        {
            using (SecureStringToBytesMarshal saltMarshalBytes = new SecureStringToBytesMarshal(salt))
            {
                byte[] protectedByteArray = Convert.FromBase64String(protectedData);
                byte[] decryptedData = ProtectedData.Unprotect(protectedByteArray, saltMarshalBytes.Bytes, DataProtectionScope.CurrentUser); //use UnprotectBinaryForUser for null checks

                using (BytesToSecureStringMarshal bytesToSecureStringMarshal = new BytesToSecureStringMarshal(ref decryptedData))
                {
                    return bytesToSecureStringMarshal.SecureString;
                }
            }
        }
    }
}
