using Microsoft.Win32;
using System.Security.Cryptography;

namespace CryptoAPI
{
    internal class SmartCardBuilder
    {
        public static string[] GetCspNameList()
        {
            // CSPの名前を取得する
            var subKeys = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Cryptography\Defaults\Provider");
            string[] cspNames = new string[0];
            if (subKeys != null)
            {
                cspNames = subKeys.GetSubKeyNames();
            }
            return cspNames;
        }

        public static CspParameters CspParamterBuilder(string cspname)
        {
            var type = Registry.GetValue(
               "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography\\Defaults\\Provider\\" + cspname,
               "Type",
               null);

            // CSPの名前を指定して、CSPを取得する
            var csp = new CspParameters();
            if (type != null)
            {
                csp.ProviderType = (int)type;
            }
            else
            {
                csp.ProviderType = 0;
            }
            csp.ProviderName = cspname;
            csp.Flags = CspProviderFlags.UseMachineKeyStore;
            return csp;
        }
    }
}
