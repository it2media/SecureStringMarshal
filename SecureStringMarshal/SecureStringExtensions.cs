using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace SecureStringMarshal
{
    public static class SecureStringExtensions
    {
        public static string ToProtectedString(this SecureString secureString, ref string salt, bool emptySaltStringAfterConversion = false)
        {
            string encrpytedString = null;

            RuntimeHelpers.PrepareConstrainedRegions(); //ensure that all operations are finshed, so the dispose is securely called
            //PS: we need to protect the code with CER-regions inside the Marshals itself again, because someone could use the Marshals standalone outside the ProtectedString-Method
            try { }
            finally
            {
                using (StringToSecureStringMarshal saltToSecureSaltMarshal = new StringToSecureStringMarshal(ref salt, emptySaltStringAfterConversion))
                {
                    using (SecureStringToBytesMarshal secureSaltMarshal = new SecureStringToBytesMarshal(saltToSecureSaltMarshal.SecureString))
                    {
                        using (SecureStringToBytesMarshal secureStringMarshal = new SecureStringToBytesMarshal(secureString))
                        {
                            encrpytedString = Convert.ToBase64String(ProtectedData.Protect(secureStringMarshal.Bytes, secureSaltMarshal.Bytes, DataProtectionScope.CurrentUser));
                        }
                    }
                }
            }

            return encrpytedString;
        }

        public static string ToProtectedString(this SecureString secureString, SecureString secureSalt)
        {
            string encrpytedString = null;

            RuntimeHelpers.PrepareConstrainedRegions();
            try { }
            finally
            {
                using (SecureStringToBytesMarshal secureSaltMarshal = new SecureStringToBytesMarshal(secureSalt))
                {
                    using (SecureStringToBytesMarshal secureStringMarshal = new SecureStringToBytesMarshal(secureString)) //this is inner, so it's deallocated first
                    {
                        encrpytedString = Convert.ToBase64String(ProtectedData.Protect(secureStringMarshal.Bytes, secureSaltMarshal.Bytes, DataProtectionScope.CurrentUser));
                    }
                }
            }

            return encrpytedString;
        }
    }
}
