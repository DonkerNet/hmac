using System;

namespace Donker.Hmac.Signing
{
    /// <summary>
    /// An exception thrown when the HMAC key repository threw an exception.
    /// </summary>
    public class HmacKeyRepositoryException : Exception
    {
        /// <summary>
        /// Initializes a new instance of <see cref="HmacKeyRepositoryException"/> using the specified message and the inner exception responsible for this exception.
        /// </summary>
        /// <param name="message">The message describing the error that occured.</param>
        /// <param name="innerException">The inner exception responsible for this exception.</param>
        public HmacKeyRepositoryException(string message, Exception innerException)
            : base(message, innerException)
        {
        }

        /// <summary>
        /// Initializes a new instance of <see cref="HmacKeyRepositoryException"/> using the specified message.
        /// </summary>
        /// <param name="message">The message describing the error that occured.</param>
        public HmacKeyRepositoryException(string message)
            : base(message)
        {
        }
    }
}