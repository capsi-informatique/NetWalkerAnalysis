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

using System.IO;
using System.Collections.Generic;
using System.Diagnostics;

namespace NetWalkerAnalysis
{
    class Logger
    {
        public static string ResultDir = "";

        /// <summary>
        /// Display some text in the console and save it to a log file
        /// </summary>
        /// <param name="data">Text to display</param>
        public static void Console(string data)
        {
            StackFrame frame = new StackFrame(1);
            string mth = frame.GetMethod().Name;
            string cls = frame.GetMethod().DeclaringType.Name;

            string message = "[" + cls + "::" + mth + "]:" + data;

            System.Console.WriteLine(message);
            File.AppendAllText(ResultDir + "\\log.txt", message + "\r\n");
        }

        /// <summary>
        /// Write some data to a log file
        /// </summary>
        /// <param name="file">File name</param>
        /// <param name="content">Content to write</param>
        public static void WriteFile(string file, List<string> content)
        {
            File.WriteAllLines(ResultDir + "\\" + file + ".txt", content.ToArray());
        }

        /// <summary>
        /// Write some data to a log file
        /// </summary>
        /// <param name="file">File name</param>
        /// <param name="content">Content to write</param>
        public static void WriteFile(string file, string content)
        {
            File.WriteAllText(ResultDir + "\\" + file + ".txt", content);
        }

        /// <summary>
        /// Write some data to a log file
        /// The file name is deducted from the callstack
        /// </summary>
        /// <param name="content"></param>
        public static void WriteFile(List<string> content)
        {
            StackFrame frame = new StackFrame(1);
            string mth = frame.GetMethod().Name;
            string cls = frame.GetMethod().DeclaringType.Name;
            WriteFile(cls + "-" + mth, content);
        }
    }
}