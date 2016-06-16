using System;

namespace Donker.Hmac.Configuration
{
    /// <summary>
    /// An exception thrown when the HMAC configuration is invalid.
    /// </summary>
    public class HmacConfigurationException : Exception
    {
        /// <summary>
        /// Initializes a new instance of <see cref="HmacConfigurationException"/> using the specified message and the inner exception responsible for this exception.
        /// </summary>
        /// <param name="message">The message describing the error that occured.</param>
        /// <param name="innerException">The inner exception responsible for this exception.</param>
        public HmacConfigurationException(string message, Exception innerException)
            : base(message, innerException)
        {
        }

        /// <summary>
        /// Initializes a new instance of <see cref="HmacConfigurationException"/> using the specified message.
        /// </summary>
        /// <param name="message">The message describing the error that occured.</param>
        public HmacConfigurationException(string message)
            : base(message)
        {
        }
    }
}