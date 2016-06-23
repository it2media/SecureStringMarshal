using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;
using System.Threading.Tasks;

[assembly: ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
namespace SecureStringMarshal
{
    /// <summary>
    /// A helper for managed code to secure marshal the handling of SecureStrings to Strings
    /// </summary>
    public class SecureStringToStringMarshal : IDisposable
    {
        #region Private Fields

        private string _string;
        private SecureString _secureString;
        private GCHandle _gcHandleString;

        #endregion

        #region Public Properties
        public SecureString SecureString
        {
            get
            {
                return _secureString;
            }
        }
        
        public string String
        {
            get
            {
                return _string;
            }            
        }

        public string GetString()
        {
            return _string;
        }
        #endregion

        #region Constructor

        [SecurityCritical]
        public SecureStringToStringMarshal(SecureString secureString)
        {
            _secureString = secureString;

            SecureStringToString();
        }

        #endregion


        /// <summary>
        /// Pins a managed string in memory writes the SecureString's unmanaged content to that managed string
        /// </summary>
        [SecurityCritical]
        private void SecureStringToString()
        {
            ClearMemory();

            unsafe
            {
                if (SecureString != null)
                {
                    _string = new string('\0', _secureString.Length);

                    _gcHandleString = new GCHandle();

                    RuntimeHelpers.PrepareConstrainedRegions();
                    try { }
                    finally
                    {
                        _gcHandleString = GCHandle.Alloc(String, GCHandleType.Pinned);
                    }

                    IntPtr stringPtr = IntPtr.Zero;

                    RuntimeHelpers.ExecuteCodeWithGuaranteedCleanup(

                        delegate
                        {                        
                            RuntimeHelpers.PrepareConstrainedRegions();
                            try { }
                            finally
                            {
                                stringPtr = Marshal.SecureStringToBSTR(SecureString);
                            }

                            RuntimeHelpers.PrepareConstrainedRegions();
                            try
                            {
                                char* pString = (char*)stringPtr;
                                char* pInsecureString = (char*)_gcHandleString.AddrOfPinnedObject();

                                for (int i = 0; i < _string.Length; i++)
                                {
                                    pInsecureString[i] = pString[i];
                                }
                            }
                            catch
                            {
                                ClearMemory();
                            }
                        },

                        delegate
                        {
                            if (stringPtr != IntPtr.Zero)
                            {
                                Marshal.ZeroFreeBSTR(stringPtr);
                            }
                        },

                        null);
                }
            }
        }
        

        #region Dispose
        public void Dispose()
        {
            ClearMemory();
        }
        #endregion
        /// <summary>
        /// Overrides the chars at the strings memory address with null characters and then releases the string again for the GC
        /// </summary>     
        [method: ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        [SecurityCritical]
        private void ClearMemory()
        {
            RuntimeHelpers.PrepareConstrainedRegions();
            try { }
            finally
            {
                //strong reliability contracts,
                //https://msdn.microsoft.com/en-us/library/ms228973(v=vs.110).aspx

                if (_gcHandleString.IsAllocated)
                {
                    unsafe
                    {
                        char* pInsecureString = (char*)_gcHandleString.AddrOfPinnedObject();
                        for (int index = 0; index < _string.Length; index++)
                        {
                            pInsecureString[index] = '\0';
                        }
                        _gcHandleString.Free();
                    }
                }
            }
        }
    }
}