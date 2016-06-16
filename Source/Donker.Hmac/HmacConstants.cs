namespace Donker.Hmac
{
    /// <summary>
    /// Contains read-only configuration values for the HMAC authentication.
    /// </summary>
    public class HmacConstants
    {
        /// <summary>
        /// The name of the HTTP Content-MD5 header: "Content-MD5".
        /// </summary>
        public const string ContentMd5HeaderName = "Content-MD5";
        /// <summary>
        /// The name of the HTTP Authorization header: "Authorization".
        /// </summary>
        public const string AuthorizationHeaderName = "Authorization";
        /// <summary>
        /// The name of the HTTP Date header: "Date".
        /// </summary>
        public const string DateHeaderName = "Date";
        /// <summary>
        /// The .NET datetime format of the HTTP Date header value: "ddd, dd MMM yyyy HH:mm:ss G\\MT".
        /// </summary>
        public const string DateHeaderFormat = "ddd, dd MMM yyyy HH:mm:ss G\\MT";
        /// <summary>
        /// The culture to use when converting a datetime to a string for the value of the HTTP Date header: "en-US".
        /// </summary>
        public const string DateHeaderCulture = "en-US";
        /// <summary>
        /// The format of the Authorization header value: "{0} {1}". Here the first parameter should be the scheme and the second the data for authorization.
        /// </summary>
        public const string AuthorizationHeaderFormat = "{0} {1}";
    }
}
