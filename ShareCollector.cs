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
using System.Collections.Generic;
using System.Management;

namespace NetWalkerAnalysis
{
    class ShareCollector
    {
        const UInt32 DISK_DRIVE = 0;
        const UInt32 PRINT_QUEUE = 1;
        const UInt32 DEVICE = 2;
        const UInt32 IPC = 3;
        const UInt32 DISK_DRIVE_ADMIN = 2147483648;
        const UInt32 PRINT_QUEUE_ADMIN = 2147483679;
        const UInt32 DEVICE_ADMIN = 2147483650;
        const UInt32 IPC_ADMIN = 2147483651;

        /// <summary>
        /// List share active on the local machine
        /// </summary>
        /// <returns>List of shares paths</returns>
        public static List<string> GetShares()
        {
            List<string> path = new List<string>();

            using (ManagementClass shares = new ManagementClass("Win32_Share", new ObjectGetOptions()))
            {
                foreach (ManagementObject share in shares.GetInstances())
                {
                    if (((UInt32)share["Type"]) == DISK_DRIVE)
                    {
                        path.Add(share["Path"].ToString());
                    }
                }
            }

            return path;
        }
    }
}