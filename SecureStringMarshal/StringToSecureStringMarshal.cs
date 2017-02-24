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
    /// A helper for managed code to secure marshal the handling of Strings to SecureStrings
    /// </summary>
    public class StringToSecureStringMarshal : IDisposable
    {
        #region Private Fields

        private bool _overrideMemory = true;
        private int _length;
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
            protected set
            {
                _secureString = value;                
            }
        }

        public SecureString GetSecureString()
        {
            return _secureString;
        }
        #endregion

        #region Constructors
        /// <summary>
        /// Pass string by ref. ATTENTION: set overrideMemory correct
        /// </summary>
        /// <param name="str"></param>
        /// <param name="overrideMemory">Set to false, if you do not want your string's memory nulled at Dispose</param>
        public StringToSecureStringMarshal(ref string str, bool overrideMemory = true)
        {
            _overrideMemory = overrideMemory;

            StringToSecureString(ref str);
        }

        /// <summary>
        /// Passed by clone, so always empties the chars in the string pointer (overrideMemory always true)
        /// </summary>
        /// <param name="str"></param>
        public StringToSecureStringMarshal(string str)
        {
            StringToSecureString(ref str);
        }
        #endregion


        /// <summary>
        /// Pins the managed string in memory and generates a SecureString from that pointer
        /// </summary>
        /// <param name="str">The managed String</param>
        private void StringToSecureString(ref string str)
        {
            _length = str.Length;

            RuntimeHelpers.PrepareConstrainedRegions();
            try { }
            finally
            {
                _gcHandleString = GCHandle.Alloc(str, GCHandleType.Pinned);
            }

            unsafe
            {
                fixed (char* passwordChars = str)
                {
                    _secureString = new SecureString((char*)passwordChars, _length);
                    _secureString.MakeReadOnly();
                }
            }
        }


        #region Dispose
        /// <summary>
        /// Do not call directly, better use a "using"-block!
        /// </summary>
        public void Dispose()
        {
            ClearMemory(_overrideMemory);
        }
        #endregion
        /// <summary>
        /// Overrides the chars at the strings memory address with null characters and then releases the string again for the GC
        /// </summary>
        private void ClearMemory(bool overrideMemory)
        {
            if (overrideMemory)
            {
                if (_gcHandleString.IsAllocated)
                {
                    unsafe
                    {
                        char* pInsecureString = (char*)_gcHandleString.AddrOfPinnedObject();
                        for (int i = 0; i < _length; i++)
                        {
                            pInsecureString[i] = '\0';
                        }
                        _gcHandleString.Free();
                    }
                }
            }
        }
    }
}
