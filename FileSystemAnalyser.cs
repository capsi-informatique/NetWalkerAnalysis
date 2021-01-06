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
using System.Text.RegularExpressions;

namespace NetWalkerAnalysis
{
    class FileSystemAnalyser
    {
        const string Pattern = ".+\\\\([a-f0-9]+-Readme.txt)$";

        /// <summary>
        /// Get the list of drive on this computer including fixed drives and USB devices excluding CD/DVD/BD-ROM
        /// </summary>
        /// <returns>String list of letters, e.g. C:\, D:\</returns>
        public static List<string> GetDisks()
        {
            DriveInfo[] drives = DriveInfo.GetDrives();
            List<string> letters = new List<string>();

            foreach (DriveInfo drive in drives)
            {
                if (drive.DriveType == DriveType.Fixed || drive.DriveType == DriveType.Removable)
                {
                    letters.Add(drive.Name);
                }
            }

            return letters;
        }

        /// <summary>
        /// Start the scan for all local drive
        /// </summary>
        /// <see cref="GetDisks"/>
        /// <returns>Path matched by the first scan</returns>
        public static List<string> Scan()
        {
            List<string> paths = new List<string>();
            foreach (string disk in GetDisks())
            {
                Logger.Console("Starting Scan of " + disk);
                Scan(disk, paths);
                Logger.Console("Scan of " + disk + " ended");
            }

            Logger.WriteFile(paths);
            return paths;
        }

        /// <summary>
        /// Scan a specific directory for file matching the NetWalker pattern
        /// Note: this function is recursive
        /// </summary>
        /// <param name="dir">Directory to scan</param>
        /// <param name="paths">List of files to fill</param>
        static void Scan(string dir, List<string> paths)
        {
            try
            {
                string[] patterns = { "*-Readme.txt", "BatchDownload.exe", "mairie.exe" };
                foreach (string pattern in patterns)
                {
                    foreach (string nFile in Directory.GetFiles(dir, pattern, SearchOption.TopDirectoryOnly))
                    {
                        paths.Add(nFile);
                        Logger.Console("!!! " + nFile);
                    }
                }

                foreach (string nDir in Directory.GetDirectories(dir))
                {
                    Scan(nDir, paths);
                }
            }
            catch (UnauthorizedAccessException e)
            {
                Logger.Console(e.Message);
            }
            catch (DirectoryNotFoundException e)
            {
                Logger.Console(e.Message);
            }
        }

        /// <summary>
        /// Search for the NetWalker Readme file in a file list
        /// </summary>
        /// <see cref="Scan(string, List{string})"/>
        /// <param name="files">File list to search in</param>
        /// <returns>Summarize of Readme found</returns>
        public static List<string> ListReadme(List<string> files)
        {
            Logger.Console("Summarize listing of detected files");
            List<string> readme = new List<string>();
            foreach (string file in files)
            {
                MatchCollection matches = Regex.Matches(file, Pattern, RegexOptions.IgnoreCase);
                if (matches.Count > 0 && !readme.Contains(matches[0].Groups[1].Value))
                {
                    readme.Add(matches[0].Groups[1].Value);
                }
            }

            readme.Sort();
            Logger.WriteFile(readme);
            return readme;
        }

        /// <summary>
        /// Search for the NetWalker Readme file in a file list on local share
        /// </summary>
        /// <see cref="ListReadme(List{string})"/>
        /// <see cref="ListReadmeNotOnShares(List{string})"/>
        /// <param name="files"></param>
        /// <returns>Summarize of Readme found</returns>
        public static List<string> ListReadmeOnShares(List<string> files)
        {
            Logger.Console("Filter detected files on shares");
            List<string> readme = new List<string>();
            List<string> shares = ShareCollector.GetShares();
            foreach (string file in files)
            {
                foreach (string share in shares)
                {
                    if (file.StartsWith(share + "\\"))
                    {
                        MatchCollection matches = Regex.Matches(file, Pattern, RegexOptions.IgnoreCase);
                        if (matches.Count > 0 && !readme.Contains(matches[0].Groups[1].Value))
                        {
                            readme.Add(matches[0].Groups[1].Value);
                        }
                    }
                }
            }

            readme.Sort();
            Logger.WriteFile(readme);
            return readme;
        }

        /// <summary>
        /// Search for the NetWalker Readme file in a file list not on local share
        /// </summary>
        /// <see cref="ListReadme(List{string})"/>
        /// <see cref="ListReadmeOnShares(List{string})"/>
        /// <param name="files"></param>
        /// <returns>Summarize of Readme found</returns>
        public static List<string> ListReadmeNotOnShares(List<string> files)
        {
            Logger.Console("Filter detected files not on shares");
            List<string> readme = new List<string>();
            List<string> shares = ShareCollector.GetShares();
            foreach (string file in files)
            {
                foreach (string share in shares)
                {
                    if (!file.StartsWith(share + "\\"))
                    {
                        MatchCollection matches = Regex.Matches(file, Pattern, RegexOptions.IgnoreCase);
                        if (matches.Count > 0 && !readme.Contains(matches[0].Groups[1].Value))
                        {
                            readme.Add(matches[0].Groups[1].Value);
                        }
                    }
                }
            }

            readme.Sort();
            Logger.WriteFile(readme);
            return readme;
        }

        /// <summary>
        /// Search for suspicious programs
        /// </summary>
        /// <param name="files">File list to search in</param>
        /// <returns>True if found</returns>
        public static bool HasSuspiciousExe(List<string> files)
        {
            foreach (string file in files)
            {
                string[] patterns = { "\\BatchDownload.exe$", "\\mairie.exe$" };
                foreach (string pattern in patterns)
                {
                    if (!file.EndsWith(pattern))
                    {
                        return true;
                    }
                }
            }
            return false;
        }
    }
}
