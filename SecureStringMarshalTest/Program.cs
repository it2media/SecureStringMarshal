using System;
using System.Collections.Generic;
using System.Linq;
using System.Security;
using System.Text;
using System.Threading.Tasks;
using IT2media.SecureStringMarshal;

namespace SecureStringMarshalTest
{
    class Program
    {
        static void Main(string[] args)
        {
            SecureString securePassword = new SecureString();
            securePassword.AppendChar('a'); securePassword.AppendChar('b'); securePassword.AppendChar('c'); securePassword.AppendChar('\uDBFF'); securePassword.AppendChar('d');

            string salt = "salt";

            string protectedString = securePassword.ToProtectedString(ref salt, false);
            Console.WriteLine(protectedString);



            SecureString secureSalt = new SecureString();
            secureSalt.AppendChar('s'); secureSalt.AppendChar('a'); secureSalt.AppendChar('l'); secureSalt.AppendChar('t');


            string protectedString2 = securePassword.ToProtectedString(secureSalt);
            Console.WriteLine(protectedString2);

            SecureString ret = protectedString.FromProtectedString(ref salt);
            SecureString ret2 = protectedString2.FromProtectedString(ref salt);

            SecureString ret3 = protectedString.FromProtectedString(secureSalt);


            Console.ReadKey();
        }
    }
}
