// Scan a Windows computer for traces of a variant of NetWalker ransomware
// Copyright(C) 2021 David Cachau
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

using Microsoft.Win32;

namespace NetWalkerAnalysis
{
    class RegistryAnalyser
    {
        /// <summary>
        /// Scan all registry for NetWalker traces
        /// Not fully implemented
        /// </summary>
        public static void Scan()
        {
            //Logger.Console("Registry scan for " + Registry.ClassesRoot.Name);
            //Scan(Registry.ClassesRoot);

            Logger.Console("Registry scan for " + Registry.Users.Name);
            Scan(Registry.Users);

            //Logger.Console("Registry scan for " + Registry.CurrentConfig.Name);
            //Scan(Registry.CurrentConfig);

            Logger.Console("Registry scan for " + Registry.LocalMachine.Name);
            Scan(Registry.LocalMachine);
        }

        /// <summary>
        /// Scan for a base registry key
        /// Not fully implemented
        /// </summary>
        /// <param name="rk"></param>
        static void Scan(RegistryKey rk)
        {
            Scan(rk, rk.Name);
        }

        /// <summary>
        /// Scan the registry
        /// Not implemented
        /// </summary>
        /// <param name="rk"></param>
        /// <param name="parent"></param>
        static void Scan(RegistryKey rk, string parent)
        {
            foreach (string k in rk.GetSubKeyNames())
            {
                if (k == rk.Name)
                {
                    Logger.Console(parent + "\\" + k);
                }
                try
                {
                    Scan(rk.OpenSubKey(k), parent + "\\" + k);
                }
                catch (System.Security.SecurityException e)
                {
                    //Logger.Console(e.Message + " - " + parent + "\\" + k);
                }
            }
        }
    }
}
