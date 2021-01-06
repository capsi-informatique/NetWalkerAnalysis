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

using System.Collections.Generic;
using System.Management;
using System.IO;
using System.Diagnostics;

namespace NetWalkerAnalysis
{
    class UserAccountCollector
    {
        /// <summary>
        /// List local user accounts
        /// </summary>
        /// <returns>List of usernames</returns>
        public static List<string> GetUsers()
        {
            Logger.Console("Collecting users");
            List<string> users = new List<string>();

            SelectQuery query = new SelectQuery("Win32_UserAccount");
            ManagementObjectSearcher searcher = new ManagementObjectSearcher(query);
            foreach (ManagementObject envVar in searcher.Get())
            {
                users.Add(envVar["Name"].ToString());
            }

            users.Sort();
            Logger.WriteFile(users);
            return users;
        }

        /// <summary>
        /// Check if the adfs user profile has been created
        /// </summary>
        /// <returns>True if present</returns>
        public static bool HasAdfs()
        {
            return Directory.Exists("C:\\Users\\adfs\\");
        }

        /// <summary>
        /// Remove a profile directory
        /// </summary>
        /// <param name="username">The username profile to remove</param>
        public static void RemoveUser(string username)
        {
            Logger.Console("Removing user profile " + username);
            Process process = new Process();
            ProcessStartInfo startInfo = new ProcessStartInfo();
            startInfo.WindowStyle = ProcessWindowStyle.Hidden;
            startInfo.FileName = "cmd";
            startInfo.Arguments = "/C rd /S /Q \"C:\\Users\\" + username + "\\\"";
            process.StartInfo = startInfo;
            process.Start();
            process.WaitForExit();
        }
    }
}
