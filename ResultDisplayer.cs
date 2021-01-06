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

namespace NetWalkerAnalysis
{
    class ResultDisplayer
    {
        /// <summary>
        /// Display a green check mark, this machine is clean
        /// </summary>
        public static void Clean()
        {
            Console.BackgroundColor = ConsoleColor.DarkGreen;
            Console.ForegroundColor = ConsoleColor.White;

            Console.WriteLine();
            Console.WriteLine("                 XX ");
            Console.WriteLine("                XX  ");
            Console.WriteLine("               XX   ");
            Console.WriteLine("              XX    ");
            Console.WriteLine("             XX     ");
            Console.WriteLine(" XX         XX      ");
            Console.WriteLine("   XX      XX       ");
            Console.WriteLine("     XX   XX        ");
            Console.WriteLine("       XXXX         ");
            Console.WriteLine();
        }

        /// <summary>
        /// Display a red cross mark, this machine was or is infected womewhere
        /// </summary>
        public static void Locked()
        {
            Console.BackgroundColor = ConsoleColor.DarkRed;
            Console.ForegroundColor = ConsoleColor.White;

            Console.WriteLine();
            Console.WriteLine(" XXX             XXX ");
            Console.WriteLine("   XXX         XXX   ");
            Console.WriteLine("     XXX     XXX     ");
            Console.WriteLine("       XXX XXX       ");
            Console.WriteLine("         XXX         ");
            Console.WriteLine("       XXX XXX       ");
            Console.WriteLine("     XXX     XXX     ");
            Console.WriteLine("   XXX         XXX   ");
            Console.WriteLine(" XXX             XXX ");
            Console.WriteLine();
        }

        /// <summary>
        /// Display a yellow exclamation, this machine is suspicious
        /// </summary>
        public static void Unclean()
        {
            Console.BackgroundColor = ConsoleColor.DarkYellow;
            Console.ForegroundColor = ConsoleColor.White;

            Console.WriteLine();
            Console.WriteLine("          XXX         ");
            Console.WriteLine("          XXX         ");
            Console.WriteLine("          XXX         ");
            Console.WriteLine("          XXX         ");
            Console.WriteLine("          XXX         ");
            Console.WriteLine("          XXX         ");
            Console.WriteLine("          XXX         ");
            Console.WriteLine("                      ");
            Console.WriteLine("          XXX         ");
            Console.WriteLine();
        }
    }
}
