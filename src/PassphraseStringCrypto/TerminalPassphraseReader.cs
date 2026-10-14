using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace PassphraseStringCrypto;

internal static class TerminalPassphraseReader
{
    private const uint __genericRead = 0x80000000;
    private const uint __genericWrite = 0x40000000;
    private const uint __fileShareRead = 0x00000001;
    private const uint __fileShareWrite = 0x00000002;
    private const uint __openExisting = 3;
    private const uint __enableEchoInput = 0x0004;
    private const int __maximumLength = 4096;
    private const int __standardError = 2;
    private const uint __echo = 0x00000008;
    private const int __terminalChangeNow = 0;

    public static string Read(string prompt)
    {
        if(OperatingSystem.IsWindows())
            return ReadWindows(prompt);

        if(OperatingSystem.IsLinux())
            return ReadLinux(prompt);

        throw new PlatformNotSupportedException(
            "Hidden terminal input is currently supported on Windows and Linux only.");
    }

    private static string ReadWindows(string prompt)
    {
        using SafeFileHandle inputHandle = CreateFile(
            "CONIN$",
            __genericRead | __genericWrite,
            __fileShareRead | __fileShareWrite,
            IntPtr.Zero,
            __openExisting,
            0,
            IntPtr.Zero);

        if(inputHandle.IsInvalid)
            throw new InvalidOperationException("No controlling terminal is available.");

        if(!GetConsoleMode(inputHandle, out uint originalMode))
            throw new Win32Exception(Marshal.GetLastWin32Error());

        char[] buffer = new char[__maximumLength];
        Console.Error.Write(prompt);
        Console.Error.Flush();

        try
        {
            if(!SetConsoleMode(inputHandle, originalMode & ~__enableEchoInput))
                throw new Win32Exception(Marshal.GetLastWin32Error());

            if(!ReadConsole(inputHandle, buffer, (uint)buffer.Length, out uint charsRead, IntPtr.Zero))
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return new string(buffer, 0, checked((int)charsRead)).TrimEnd('\r', '\n');
        }
        finally
        {
            Array.Clear(buffer);
            SetConsoleMode(inputHandle, originalMode);
            Console.Error.WriteLine();
        }
    }

    private static string ReadLinux(string prompt)
    {
        if(IsATty(__standardError) != 1)
            throw new InvalidOperationException("No controlling terminal is available.");

        int terminalFd = DuplicateFileDescriptor(__standardError);
        if(terminalFd < 0)
            throw new Win32Exception(Marshal.GetLastWin32Error());

        using var terminalHandle = new SafeFileHandle(new IntPtr(terminalFd), ownsHandle: true);
        using var terminalStream = new FileStream(terminalHandle, FileAccess.Read);
        using var terminalReader = new StreamReader(
            terminalStream,
            Encoding.UTF8,
            detectEncodingFromByteOrderMarks: false,
            bufferSize: 256,
            leaveOpen: true);

        if(GetTerminalAttributes(terminalFd, out TerminalAttributes originalMode) != 0)
            throw new Win32Exception(Marshal.GetLastWin32Error());

        TerminalAttributes noEchoMode = originalMode;
        noEchoMode.LocalFlags &= ~__echo;

        Console.Error.Write(prompt);
        Console.Error.Flush();

        try
        {
            if(SetTerminalAttributes(terminalFd, __terminalChangeNow, ref noEchoMode) != 0)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            string value = terminalReader.ReadLine()
                ?? throw new InvalidOperationException("Unable to read the passphrase.");
            if(value.Length > __maximumLength)
                throw new InvalidOperationException("Passphrase is too long.");

            return value;
        }
        finally
        {
            SetTerminalAttributes(terminalFd, __terminalChangeNow, ref originalMode);
            Console.Error.WriteLine();
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TerminalAttributes
    {
        public uint InputFlags;
        public uint OutputFlags;
        public uint ControlFlags;
        public uint LocalFlags;
        public byte LineDiscipline;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
        public byte[] ControlCharacters;

        public uint InputSpeed;
        public uint OutputSpeed;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFile(
        string fileName,
        uint desiredAccess,
        uint shareMode,
        IntPtr securityAttributes,
        uint creationDisposition,
        uint flagsAndAttributes,
        IntPtr templateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetConsoleMode(SafeFileHandle consoleHandle, out uint mode);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetConsoleMode(SafeFileHandle consoleHandle, uint mode);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ReadConsole(
        SafeFileHandle consoleInput,
        [Out] char[] buffer,
        uint charsToRead,
        out uint charsRead,
        IntPtr inputControl);

    [DllImport("libc", EntryPoint = "isatty", SetLastError = true)]
    private static extern int IsATty(int fileDescriptor);

    [DllImport("libc", EntryPoint = "dup", SetLastError = true)]
    private static extern int DuplicateFileDescriptor(int fileDescriptor);

    [DllImport("libc", EntryPoint = "tcgetattr", SetLastError = true)]
    private static extern int GetTerminalAttributes(
        int fileDescriptor,
        out TerminalAttributes attributes);

    [DllImport("libc", EntryPoint = "tcsetattr", SetLastError = true)]
    private static extern int SetTerminalAttributes(
        int fileDescriptor,
        int optionalActions,
        ref TerminalAttributes attributes);
}
