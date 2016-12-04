using System;

namespace Donker.Hmac.Signing
{
    /// <summary>
    /// Key repository that returns a single key for one specific user.
    /// </summary>
    public class SingleUserHmacKeyRepository : IHmacKeyRepository
    {
        /// <summary>
        /// Gets the username to only return the key for.
        /// </summary>
        public string Username { get; }
        /// <summary>
        /// Gets the key to return for the username.
        /// </summary>
        public string Key { get; }
        /// <summary>
        /// Gets the comparison to use when checking if the username matches.
        /// </summary>
        public StringComparison UsernameComparison { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="SingleHmacKeyRepository"/> class using the specified username, key and username comparison.
        /// </summary>
        /// <param name="username">The username to only return the key for.</param>
        /// <param name="key">The key to return for the username.</param>
        /// <param name="usernameComparison">The comparer to use when checking if the username matches.</param>
        /// <exception cref="ArgumentNullException">The username or key is null.</exception>
        /// <exception cref="ArgumentException">The username or key is empty, or the username comparison is not a valid <see cref="StringComparison"/> value.</exception>
        public SingleUserHmacKeyRepository(string username, string key, StringComparison usernameComparison)
        {
            if (username == null)
                throw new ArgumentNullException(nameof(username), "The username cannot be null.");
            if (username.Length == 0)
                throw new ArgumentException("The username cannot be empty.", nameof(username));
            if (key == null)
                throw new ArgumentNullException(nameof(key), "The key cannot be null.");
            if (key.Length == 0)
                throw new ArgumentException("The key cannot be empty.", nameof(key));
            if (!Enum.IsDefined(typeof(StringComparison), usernameComparison))
                throw new ArgumentException("The username comparison is not a valid StringComparison value.", nameof(usernameComparison));

            Username = username;
            Key = key;
            UsernameComparison = usernameComparison;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="SingleHmacKeyRepository"/> class using the specified username, key and ordinal case-sensitive comparison.
        /// </summary>
        /// <param name="username">The username to only return the key for.</param>
        /// <param name="key">The key to return for the username.</param>
        /// <exception cref="ArgumentNullException">The username or key is null.</exception>
        /// <exception cref="ArgumentException">The username or key is empty.</exception>
        public SingleUserHmacKeyRepository(string username, string key)
            :this(username, key, StringComparison.Ordinal)
        {
        }

        /// <summary>
        /// Checks if the username matches the one of the repository and returns the key if so.
        /// </summary>
        /// <param name="username">The username to retrieve the key for.</param>
        /// <returns>The key as a <see cref="string"/> if the username matches; otherwise, <c>null</c>.</returns>
        public string GetHmacKeyForUsername(string username)
        {
            if (string.Equals(username, Username, UsernameComparison))
                return Key;
            return null;
        }
    }
}