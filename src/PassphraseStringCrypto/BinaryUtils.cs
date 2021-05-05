using System;

namespace PassphraseStringCrypto
{
    /// <summary>
    /// Static utility methods for reading and writing binary encoded values.
    /// </summary>
    public static class BinaryUtils
    {
        /// <summary>
        /// Reads a binary encoded <see cref="ushort"/> from the provided bytes.
        /// </summary>
        /// <param name="buf">The byte span to read from; with a length of at least two.</param>
        /// <returns>The <see cref="ushort"/> that was read.</returns>
        public static ushort ReadUInt16(Span<byte> buf)
        {
            ushort v = (ushort)(buf[0] << 8);
            v |= (ushort)buf[1];
            return v;
        }

        /// <summary>
        /// Binary encode a <see cref="ushort"/>, and write the bytes into the provided byte span.
        /// </summary>
        /// <param name="v">The value to write.</param>
        /// <param name="buf">The byte span to write into, with a length of at least two.</param>
        public static void WriteUInt16(ushort v, Span<byte> buf)
        {
            buf[0] = (byte)(v >> 8);
            buf[1] = (byte)v;
        }
    }
}
