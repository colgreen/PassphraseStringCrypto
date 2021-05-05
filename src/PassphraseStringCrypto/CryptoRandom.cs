using System;
using System.Security.Cryptography;

namespace PassphraseStringCrypto
{
    /// <summary>
    /// Static utility methods for obtaining cryptographic random bytes.
    /// </summary>
    public static class CryptoRandom
    {
        // Note. RandomNumberGenerator is IDisposable, but its lifetime as a static field is for the entire lifetime of the containing process, therefore
        // there is no need to explicitly dispose of this object; it will be disposed off when the process ends.
        private static readonly RandomNumberGenerator __cryptoRng = RandomNumberGenerator.Create();
        private static readonly object __cryptoRngLock = new object();

        #region Public Static Methods

        /// <summary>
        /// Writes cryptographic quality random bytes into a sub-segment of the provided byte array.
        /// </summary>
        /// <param name="buf">The array to fill.</param>
        public static void WriteCryptoRandomBytes(Span<byte> buf)
        {
            // Note. Some implementations (i.e. subclasses) RandomNumberGenerator may allow concurrent callers, however, the framework documentation does not state this,
            // therefore to ensure this code is safe in all scenarios we synchronise access. Alternatively we could instantiate a new RandomNumberGenerator on each 
            // call; which of these approaches to take is really a performance trade off. Overall it probably doesn't matter, but the approach used here will at least 
            // avoid excessive initialisation, object allocation, and garbage collection costs if this method is called with high frequency.
            lock(__cryptoRngLock)
            {
                __cryptoRng.GetBytes(buf);
            }
        }

        #endregion
    }
}
