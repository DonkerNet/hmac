using System;
using System.Collections.Generic;
using System.Text;

namespace Donker.Hmac.Configuration
{
    /// <summary>
    /// The configuration used for signing and validating requests.
    /// </summary>
    [Serializable]
    public class HmacConfiguration : IHmacConfiguration
    {
        /// <summary>
        /// Gets or sets the name of the configuration.
        /// </summary>
        public string Name { get; set; }
        /// <summary>
        /// Gets or sets the name of the HTTP header containing the username.
        /// </summary>
        public string UserHeaderName { get; set; }
        /// <summary>
        /// Gets or sets the authorization scheme used in the Authorization HTTP header.
        /// </summary>
        public string AuthorizationScheme { get; set; }
        /// <summary>
        /// Gets or sets the string used to separate the data to sign when converting it to a single string.
        /// </summary>
        public string SignatureDataSeparator { get; set; }
        /// <summary>
        /// Gets or sets the encoding to use when converting string values to bytes during the signing process.
        /// </summary>
        public string SignatureEncoding { get; set; }
        /// <summary>
        /// Gets or sets the name of the HMAC algorithm to use for signing.
        /// </summary>
        public string HmacAlgorithm { get; set; }
        /// <summary>
        /// Gets or sets the maximum allowed age of a request, compared to the current system time. Recommended.
        /// </summary>
        public TimeSpan? MaxRequestAge { get; set; }
        /// <summary>
        /// Gets or sets if the request URI should be included with signing. Recommended.
        /// </summary>
        public bool SignRequestUri { get; set; }
        /// <summary>
        /// Gets or sets if the body of the request should be validated against the Content-MD5 header. Recommended.
        /// </summary>
        public bool ValidateContentMd5 { get; set; }
        /// <summary>
        /// Gets or sets the names of entire headers (both name and values) to canonicalize and include in the signature.
        /// </summary>
        public List<string> Headers { get; set; }

        /// <summary>
        /// Creates a new <see cref="HmacConfiguration"/> object that is a copy of the current instance and can be modified without affecting the original.
        /// </summary>
        /// <returns>
        /// A new <see cref="HmacConfiguration"/> object that is a copy of this instance and can be modified without affecting the original.
        /// </returns>
        public HmacConfiguration Clone()
        {
            HmacConfiguration configuration = new HmacConfiguration
            {
                Name = Name,
                UserHeaderName = UserHeaderName,
                AuthorizationScheme = AuthorizationScheme,
                SignatureDataSeparator = SignatureDataSeparator,
                SignatureEncoding = SignatureEncoding,
                HmacAlgorithm = HmacAlgorithm,
                MaxRequestAge = MaxRequestAge,
                SignRequestUri = SignRequestUri,
                ValidateContentMd5 = ValidateContentMd5
            };

            if (Headers != null)
                configuration.Headers = new List<string>(Headers);

            return configuration;
        }

        /// <summary>
        /// Creates a new <see cref="HmacConfiguration"/> object that is a copy of the current instance and can be modified without affecting the original.
        /// </summary>
        /// <returns>
        /// A new <see cref="HmacConfiguration"/> object that is a copy of this instance and can be modified without affecting the original.
        /// </returns>
        object ICloneableConfiguration.Clone() => Clone();
    }
}