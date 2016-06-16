using System;

namespace Donker.Hmac.Signing
{
    /// <summary>
    /// Key repository that always returns the same key, no matter for which user it's retrieved.
    /// </summary>
    public class SingleHmacKeyRepository : IHmacKeyRepository
    {
        /// <summary>
        /// Gets the key to return for every user.
        /// </summary>
        public string Key { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="SingleHmacKeyRepository"/> class using the specified key.
        /// </summary>
        /// <param name="key">The key to return for every user.</param>
        /// <exception cref="ArgumentNullException">The key is null.</exception>
        /// <exception cref="ArgumentException">The key is empty.</exception>
        public SingleHmacKeyRepository(string key)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key), "The key cannot be null.");
            if (key.Length == 0)
                throw new ArgumentException("The key cannot be empty.", nameof(key));

            Key = key;
        }

        /// <summary>
        /// Gets the key, no matter for which user it's retrieved.
        /// </summary>
        /// <param name="username">The username to retrieve the key for. This parameter is ignored.</param>
        /// <returns>The key as a <see cref="string"/>.</returns>
        public string GetHmacKeyForUsername(string username)
        {
            return Key;
        }
    }
}