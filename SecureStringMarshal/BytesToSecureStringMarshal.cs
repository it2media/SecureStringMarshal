using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;
using System.Threading.Tasks;

namespace IT2media.SecureStringMarshal
{
    /// <summary>
    /// A helper for managed code to secure marshal the handling of byte[] to SecureStrings
    /// </summary>
    public class BytesToSecureStringMarshal: IDisposable
    {
        #region Private Fields

        private int _length;
        private string _string;
        private SecureString _secureString;
        private GCHandle _gcHandleString;
        private GCHandle _gcHandleByteArray;

        #endregion

        #region Public Properties
        public SecureString SecureString
        {
            get
            {
                return _secureString;
            }
        }
        #endregion

        #region Constructor
        public BytesToSecureStringMarshal(ref byte[] bytes)
        {
            BytesToSecureString(ref bytes);
        }
        #endregion


        /// <summary>
        /// Pins the managed byte[] in memory and generates a SecureString from that pointer
        /// </summary>
        /// <param name="bytes"></param>
        private void BytesToSecureString(ref byte[] bytes)
        {
            ClearMemory();

            _length = bytes.Length;

            if (bytes != null & bytes.Length > 0)
            {
                _gcHandleString = new GCHandle();
                _gcHandleByteArray = new GCHandle();

                RuntimeHelpers.PrepareConstrainedRegions();
                try { }
                finally
                {
                    _gcHandleByteArray = GCHandle.Alloc(bytes, GCHandleType.Pinned);


                    _string = Encoding.Unicode.GetString(bytes); //To Unicode

                    _gcHandleString = GCHandle.Alloc(_string, GCHandleType.Pinned);
                }

                unsafe
                {
                    fixed (char* passwordChars = _string)
                    {
                        _secureString = new SecureString((char*)passwordChars, _string.Length);
                        _secureString.MakeReadOnly();
                    }
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
        /// Overrides the chars at the strings memory address with null characters and the bytes in the byte[] with zeros, and then releases the string and the byte[] again for the GC
        /// </summary>
        private void ClearMemory()
        {
            if (_gcHandleByteArray.IsAllocated)
            {
                unsafe
                {
                    byte* pInsecureByteArray = (byte*)_gcHandleByteArray.AddrOfPinnedObject();
                    for (int i = 0; i < _length; i++)
                    {
                        pInsecureByteArray[i] = 0;
                    }
                    _gcHandleByteArray.Free();
                }
            }

            if (_gcHandleString.IsAllocated)
            {
                unsafe
                {
                    char* pInsecureString = (char*)_gcHandleString.AddrOfPinnedObject();
                    for (int i = 0; i < _string.Length; i++)
                    {
                        pInsecureString[i] = '\0';
                    }
                    _gcHandleString.Free();
                }
            }
        }
    }
}
