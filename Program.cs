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

using System;
using System.IO;
using System.Collections.Generic;

namespace NetWalkerAnalysis
{
    class Program
    {
        /// <summary>
        /// The entry point of the analyser
        /// </summary>
        /// <param name="args">Command line args</param>
        static void Main(string[] args)
        {
            Logger.ResultDir = "C:\\NWA-(" + HostDataCollector.GetHostname() + ")-Result-" + DateTime.Now.ToString("yyyy-MM-dd-HH-mm-ss");
            Directory.CreateDirectory(Logger.ResultDir);

            Logger.Console("Running on " + (HostDataCollector.GetHostname()));

            if (HostDataCollector.IsAdministrator())
            {
                Logger.Console("Running as Administrator, continue");
            }
            else
            {
                Logger.Console("Not running as Administrator, abort !");
                Console.ReadLine();
                System.Environment.Exit(1);
            }


            Logger.Console("Mounted drives:");
            foreach (string l in FileSystemAnalyser.GetDisks())
            {
                Logger.Console(" - " + l);
            }
            Logger.WriteFile("Drives", FileSystemAnalyser.GetDisks());

            Logger.Console("Shares:");
            foreach (string s in ShareCollector.GetShares())
            {
                Logger.Console(" - " + s);
            }
            Logger.WriteFile("Shares", ShareCollector.GetShares());

            List<string> files = FileSystemAnalyser.Scan();
            List<string> allReadme = FileSystemAnalyser.ListReadme(files);
            List<string> sharesReadme = FileSystemAnalyser.ListReadmeOnShares(files);
            List<string> notSharesReadme = FileSystemAnalyser.ListReadmeNotOnShares(files);
            bool exePresent = FileSystemAnalyser.HasSuspiciousExe(files);

            if (allReadme.Count > 0)
            {
                Logger.Console("!!!!! Readme file detected, this machine is compromised !!!!!");
            }

            List<string> users = UserAccountCollector.GetUsers();
            if (users.Contains("adfs"))
            {
                Logger.Console("!!!!! adfs account detected, this machine may be compromised !!!!!");
            }

            Logger.WriteFile("Malicious-Present", exePresent ? "True" : "False");

            // don4t remove the ADFS direcotry
            //UserAccountCollector.RemoveUser("adfs");
            // This is unused by our variant of NetWalker
            //RegistryAnalyser.Scan();


            Logger.WriteFile("ADFS-Present", UserAccountCollector.HasAdfs() ? "True" : "False");

            if (allReadme.Count > 0 || exePresent)
            {
                ResultDisplayer.Locked();
            }
            else if (UserAccountCollector.HasAdfs())
            {
                ResultDisplayer.Unclean();
            }
            else
            {
                ResultDisplayer.Clean();
            }

            Console.WriteLine("Press Enter to quit...");
            Console.ReadLine();
        }
    }
}