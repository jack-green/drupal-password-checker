using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Drupass
{
    class Program
    {
        static void Main(string[] args)
        {
            var password = "password";
            var hashedPassword = "$S$DI3icqig3jyMv7n./ZLdJaV9H0s90uyRiJjeSnFPK32zo4Q.jj.8";

            var success = DrupalPassword.CheckPassword(password, hashedPassword);
            Console.WriteLine($"Success?:        {(success ? "YES!" : "No.")}");
            Console.ReadKey();
        }
    }
}
