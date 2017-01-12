using System;
using System.Collections.Generic;
using System.Text;

namespace Donker.Hmac.Configuration
{
    /// <summary>
    /// The configuration used for signing and validating requests.
    /// </summary>
    public interface IHmacConfiguration : ICloneableConfiguration
    {
        /// <summary>
        /// Gets or sets the name of the configuration.
        /// </summary>
        string Name { get; set; }
        /// <summary>
        /// Gets or sets the name of the HTTP header containing the username.
        /// </summary>
        string UserHeaderName { get; set; }
        /// <summary>
        /// Gets or sets the authorization scheme used in the Authorization HTTP header.
        /// </summary>
        string AuthorizationScheme { get; set; }
        /// <summary>
        /// Gets or sets the string used to separate the data to sign when converting it to a single string.
        /// </summary>
        string SignatureDataSeparator { get; set; }
        /// <summary>
        /// Gets or sets the encoding to use when converting string values to bytes during the signing process.
        /// </summary>
        string SignatureEncoding { get; set; }
        /// <summary>
        /// Gets or sets the name of the HMAC algorithm to use for signing.
        /// </summary>
        string HmacAlgorithm { get; set; }
        /// <summary>
        /// Gets or sets the maximum allowed age of a request, compared to the current system time. Recommended.
        /// </summary>
        TimeSpan? MaxRequestAge { get; set; }
        /// <summary>
        /// Gets or sets if the request URI should be included with signing. Recommended.
        /// </summary>
        bool SignRequestUri { get; set; }
        /// <summary>
        /// Gets or sets if the body of the request should be validated against the Content-MD5 header. Recommended.
        /// </summary>
        bool ValidateContentMd5 { get; set; }
        /// <summary>
        /// Gets or sets the names of entire headers (both name and values) to canonicalize and include in the signature.
        /// </summary>
        List<string> Headers { get; set; }
    }
}