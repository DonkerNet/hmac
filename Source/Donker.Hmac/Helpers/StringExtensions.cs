using System;
using System.Text;

namespace Donker.Hmac.Helpers
{
    /// <summary>
    /// Extension methods for <see cref="string"/> objects.
    /// </summary>
    public static class StringExtensions
    {
        /// <summary>
        /// Replaces sequences of whitespace with a single space character.
        /// </summary>
        /// <param name="value">The text to normalize the whitespace for.</param>
        /// <returns>The normalized text as a <see cref="string"/>.</returns>
        public static string NormalizeWhiteSpace(this string value)
        {
            if (value == null)
                throw new ArgumentNullException(nameof(value), "The text cannot be null.");
            if (value.Length == 0)
                return value;

            StringBuilder resultBuilder = new StringBuilder();

            bool prevWasWs = false;

            foreach (char c in value.Trim())
            {
                if (char.IsWhiteSpace(c))
                {
                    if (!prevWasWs)
                    {
                        resultBuilder.Append(' ');
                        prevWasWs = true;
                    }
                }
                else
                {
                    resultBuilder.Append(c);
                    prevWasWs = false;
                }
            }

            return resultBuilder.ToString();
        }
    }
}