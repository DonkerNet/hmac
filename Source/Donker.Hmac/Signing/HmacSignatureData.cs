using System;
using System.Collections.Specialized;

namespace Donker.Hmac.Signing
{
    /// <summary>
    /// Contains all the data to sign.
    /// </summary>
    [Serializable]
    public class HmacSignatureData
    {
        /// <summary>
        /// Gets or sets the key to use for signing.
        /// </summary>
        public string Key { get; set; }
        /// <summary>
        /// Gets or sets the HTTP method of the request.
        /// </summary>
        public string HttpMethod { get; set; }
        /// <summary>
        /// Gets or sets the Content-MD5 hash of the request body.
        /// </summary>
        public string ContentMd5 { get; set; }
        /// <summary>
        /// Gets or sets the Content-Type of the body.
        /// </summary>
        public string ContentType { get; set; }
        /// <summary>
        /// Gets or sets the timestamp of the request.
        /// </summary>
        public string Date { get; set; }
        /// <summary>
        /// Gets or sets the username associated with the key.
        /// </summary>
        public string Username { get; set; }
        /// <summary>
        /// Gets or sets the full request URI the request is meant for.
        /// </summary>
        public string RequestUri { get; set; }
        /// <summary>
        /// Gets or sets the headers to include with signing.
        /// </summary>
        public NameValueCollection Headers { get; set; }
    }
}