using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;
using System.Threading.Tasks;

namespace SecureStringMarshal
{
    /// <summary>
    /// A helper for managed code to secure marshal the handling of SecureStrings to byte[]
    /// </summary>
    public class SecureStringToBytesMarshal : IDisposable
    {
        #region Private Fields
        
        private byte[] _bytes;
        private SecureString _secureString;
        private GCHandle _gcHandleBytes;

        #endregion

        #region Public Properties
        public SecureString SecureString
        {
            get
            {
                return _secureString;
            }
        }

        public byte[] Bytes
        {
            get
            {
                return _bytes;
            }
            protected set { _bytes = value; }
        }
        public byte[] GetBytes()
        {
            return _bytes;
        }

        #endregion

        #region Constructor
        public SecureStringToBytesMarshal(SecureString secureString)
        {
            _secureString = secureString;

            SecureStringToBytes();
        }
        #endregion


        /// <summary>
        /// Pins a byte[] in memory and reads the SecureString's unmanaged content into that byte[]
        /// </summary>
        private void SecureStringToBytes()
        {
            ClearMemory();

            unsafe
            {
                if (SecureString != null)
                {
                    _bytes = new byte[_secureString.Length * 2]; //Unicode, so two bytes per char
                    
                    _gcHandleBytes = new GCHandle();
                    
                    RuntimeHelpers.PrepareConstrainedRegions();
                    try { }
                    finally
                    {
                        _gcHandleBytes = GCHandle.Alloc(_bytes, GCHandleType.Pinned);
                    }

                    IntPtr bytePtr = IntPtr.Zero;

                    RuntimeHelpers.ExecuteCodeWithGuaranteedCleanup(

                        delegate
                        {
                            RuntimeHelpers.PrepareConstrainedRegions();
                            try { }
                            finally
                            {
                                bytePtr = Marshal.SecureStringToGlobalAllocUnicode(_secureString); //ensure this finishes, only to ensure we can clean up
                            }

                            RuntimeHelpers.PrepareConstrainedRegions();
                            try
                            {
                                byte* pByteArray = (byte*)bytePtr;
                                byte* pInsecureByteArray = (byte*)_gcHandleBytes.AddrOfPinnedObject();
                                
                                for (int i = 0; i < _secureString.Length * 2; i = i + 2)
                                {
                                    pInsecureByteArray[i] = pByteArray[i];
                                    pInsecureByteArray[i + 1] = pByteArray[i + 1];
                                    //throw new Exception("ups"); the ClearMemory is triggered and the CER-finally enrues possible already written bytes are cleared
                                }
                            }
                            catch
                            {
                                ClearMemory();
                            }
                        },

                        delegate
                        {                            
                            if (bytePtr != IntPtr.Zero)
                            {
                                Marshal.ZeroFreeGlobalAllocUnicode(bytePtr);
                            }
                        },

                        null);
                }
            }
        }


        #region Dispose
        /// <summary>
        /// Do not call directly, better use a "using"-block!
        /// </summary>
        public void Dispose()
        {
            ClearMemory();
        }

        #endregion
        /// <summary>
        /// Overrides the bytes in the byte[] with zeros and then releases the byte[] again for the GC
        /// </summary>
        private void ClearMemory()
        {
            RuntimeHelpers.PrepareConstrainedRegions();
            try { }
            finally
            {
                if (_gcHandleBytes.IsAllocated)
                {
                    unsafe
                    {
                        byte* pInsecureByteArray = (byte*)_gcHandleBytes.AddrOfPinnedObject();
                        for (int i = 0; i < _bytes.Length; i++)
                        {
                            pInsecureByteArray[i] = 0;
                        }
                        _gcHandleBytes.Free();
                    }
                }
            }
        }        
    }
}