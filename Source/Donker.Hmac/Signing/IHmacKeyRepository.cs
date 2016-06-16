namespace Donker.Hmac.Signing
{
    /// <summary>
    /// A repository that is used for retrieving HMAC keys used for signing.
    /// </summary>
    public interface IHmacKeyRepository
    {
        /// <summary>
        /// Fetches the HMAC key associated with the specified username.
        /// </summary>
        /// <param name="username">The username to fetch the key for.</param>
        /// <returns>The HMAC key as a <see cref="string"/> when found; otherwise, <c>null</c>.</returns>
        string GetHmacKeyForUsername(string username);
    }
}