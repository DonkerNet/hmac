using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Web;
using Donker.Hmac.Configuration;
using Donker.Hmac.Helpers;

namespace Donker.Hmac.Signing
{
    /// <summary>
    /// This class allows for the creation of signatures for an HTTP request.
    /// </summary>
    public class HmacSigner : IHmacSigner
    {
        /// <summary>
        /// Gets the configuration used for signing and validating requests.
        /// </summary>
        protected IHmacConfiguration HmacConfiguration { get; }
        /// <summary>
        /// Gets the repository that is used for retrieving keys used for signing.
        /// </summary>
        protected IHmacKeyRepository HmacKeyRepository { get; }
        /// <summary>
        /// Gets the culture information for the value of the HTTP Date header.
        /// </summary>
        protected CultureInfo DateHeaderCulture { get; }
        /// <summary>
        /// Gets the <see cref="MD5"/> instance used for hashing the request body.
        /// </summary>
        protected MD5 Md5 { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="HmacSigner"/> class using the specified configuration and key repository.
        /// </summary>
        /// <param name="configuration">The configuration used for signing.</param>
        /// <param name="keyRepository">The repository used for retrieving the key associated with the user.</param>
        /// <exception cref="ArgumentNullException">The configuration or key repository is null.</exception>
        public HmacSigner(IHmacConfiguration configuration, IHmacKeyRepository keyRepository)
        {
            if (configuration == null)
                throw new ArgumentNullException(nameof(configuration), "The configuration cannot be null.");
            if (keyRepository == null)
                throw new ArgumentNullException(nameof(keyRepository), "The key repository cannot be null.");

            HmacConfiguration = configuration;
            HmacKeyRepository = keyRepository;
            DateHeaderCulture = new CultureInfo(HmacConstants.DateHeaderCulture);
            Md5 = MD5.Create();
        }

        /// <summary>
        /// Gets all required signature data, if found, from an HTTP request message.
        /// </summary>
        /// <param name="request">The request message to get the data from.</param>
        /// <returns>The extracted data as an <see cref="HmacSignatureData"/> object.</returns>
        /// <exception cref="ArgumentNullException">The request is null.</exception>
        /// <exception cref="HmacKeyRepositoryException">A problem occured when trying to retrieve a key based on the request.</exception>
        public virtual HmacSignatureData GetSignatureDataFromHttpRequest(HttpRequestMessage request)
        {
            if (request == null)
                throw new ArgumentNullException(nameof(request), "The request cannot be null.");

            HmacRequestWrapper requestWrapper = new HmacRequestWrapper(request);
            return GetSignatureDataFromHttpRequest(requestWrapper);
        }

        /// <summary>
        /// Gets all required signature data, if found, from an HTTP request.
        /// </summary>
        /// <param name="request">The request to get the data from.</param>
        /// <returns>The extracted data as an <see cref="HmacSignatureData"/> object.</returns>
        /// <exception cref="ArgumentNullException">The request is null.</exception>
        /// <exception cref="HmacKeyRepositoryException">A problem occured when trying to retrieve a key based on the request.</exception>
        public virtual HmacSignatureData GetSignatureDataFromHttpRequest(HttpRequestBase request)
        {
            if (request == null)
                throw new ArgumentNullException(nameof(request), "The request cannot be null.");

            HmacRequestWrapper requestWrapper = new HmacRequestWrapper(request);
            return GetSignatureDataFromHttpRequest(requestWrapper);
        }

        /// <summary>
        /// Creates a HMAC signature from the supplied data.
        /// </summary>
        /// <param name="signatureData">The data to create a signature from.</param>
        /// <returns>The signature as a <see cref="string"/>.</returns>
        /// <exception cref="ArgumentNullException">The signature data is null.</exception>
        /// <exception cref="ArgumentException">The key from the signature data is null or empty.</exception>
        /// <exception cref="HmacConfigurationException">One or more of the configuration parameters are invalid.</exception>
        public virtual string CreateSignature(HmacSignatureData signatureData)
        {
            if (signatureData == null)
                throw new ArgumentNullException(nameof(signatureData), "The signature data cannot be null.");
            if (HmacConfiguration.CharacterEncoding == null)
                throw new HmacConfigurationException("The character encoding cannot be null.");
            if (string.IsNullOrEmpty(signatureData.Key))
                throw new ArgumentException("The key cannot be null or empty.", nameof(signatureData));

            string headerString = signatureData.Headers != null
                ? CreateCanonicalizedHeadersString(signatureData.Headers)
                : null;

            string representation = string.Join(
                HmacConfiguration.SignatureDataSeparator ?? string.Empty,
                signatureData.HttpMethod,
                signatureData.ContentMd5,
                signatureData.ContentType,
                signatureData.Date,
                signatureData.Username,
                headerString,
                HmacConfiguration.SignRequestUri ? signatureData.RequestUri : null);

            byte[] keyBytes = HmacConfiguration.CharacterEncoding.GetBytes(signatureData.Key);
            byte[] representationBytes = HmacConfiguration.CharacterEncoding.GetBytes(representation);

            HMAC hmac;

            try
            {
                hmac = HMAC.Create(HmacConfiguration.HmacAlgorithm);
            }
            catch (Exception ex)
            {
                throw new HmacConfigurationException("The HMAC implemenation instance could not be created from the configured algorithm name.", ex);
            }

            hmac.Key = keyBytes;
            byte[] hash = hmac.ComputeHash(representationBytes);
            return Convert.ToBase64String(hash);
        }

        /// <summary>
        /// Computes an MD5 hash from a stream.
        /// </summary>
        /// <param name="content">The content to hash.</param>
        /// <returns>The hash as a <see cref="byte"/> array.</returns>
        /// <exception cref="ArgumentNullException">The content is null.</exception>
        /// <exception cref="HmacConfigurationException">One or more of the configuration parameters are invalid.</exception>
        public byte[] CreateMd5Hash(Stream content)
        {
            if (content == null)
                throw new ArgumentNullException(nameof(content), "The content cannot be null.");
            if (HmacConfiguration.CharacterEncoding == null)
                throw new HmacConfigurationException("The character encoding cannot be null.");

            if (content.CanSeek)
                content.Seek(0, SeekOrigin.Begin);
            
            byte[] hashBytes = Md5.ComputeHash(content);
            return hashBytes;
        }

        /// <summary>
        /// Computes an MD5 hash from a byte array.
        /// </summary>
        /// <param name="content">The content to hash.</param>
        /// <returns>The hash as a <see cref="byte"/> array.</returns>
        /// <exception cref="ArgumentNullException">The content is null.</exception>
        /// <exception cref="HmacConfigurationException">One or more of the configuration parameters are invalid.</exception>
        public byte[] CreateMd5Hash(byte[] content)
        {
            if (content == null)
                throw new ArgumentNullException(nameof(content), "The content cannot be null.");
            if (HmacConfiguration.CharacterEncoding == null)
                throw new HmacConfigurationException("The character encoding cannot be null.");

            byte[] hashBytes = Md5.ComputeHash(content);
            return hashBytes;
        }

        /// <summary>
        /// Computes an MD5 hash from a string.
        /// </summary>
        /// <param name="content">The content to hash.</param>
        /// <returns>The hash as a <see cref="byte"/> array.</returns>
        /// <exception cref="ArgumentNullException">The content is null.</exception>
        /// <exception cref="HmacConfigurationException">One or more of the configuration parameters are invalid.</exception>
        public byte[] CreateMd5Hash(string content)
        {
            if (content == null)
                throw new ArgumentNullException(nameof(content), "The content cannot be null.");
            if (HmacConfiguration.CharacterEncoding == null)
                throw new HmacConfigurationException("The character encoding cannot be null.");

            byte[] contentBytes = HmacConfiguration.CharacterEncoding.GetBytes(content);
            byte[] hashBytes = Md5.ComputeHash(contentBytes);
            return hashBytes;
        }

        /// <summary>
        /// Computes an MD5 hash from a stream and returns it as a base64 converted string.
        /// </summary>
        /// <param name="content">The content to hash.</param>
        /// <returns>The hash as a base64 <see cref="string"/>.</returns>
        /// <exception cref="ArgumentNullException">The content is null.</exception>
        /// <exception cref="HmacConfigurationException">One or more of the configuration parameters are invalid.</exception>
        public string CreateBase64Md5Hash(Stream content)
        {
            byte[] hashBytes = CreateMd5Hash(content);
            return Convert.ToBase64String(hashBytes);
        }

        /// <summary>
        /// Computes an MD5 hash from a byte array and returns it as a base64 converted string.
        /// </summary>
        /// <param name="content">The content to hash.</param>
        /// <returns>The hash as a base64 <see cref="string"/>.</returns>
        /// <exception cref="ArgumentNullException">The content is null.</exception>
        /// <exception cref="HmacConfigurationException">One or more of the configuration parameters are invalid.</exception>
        public string CreateBase64Md5Hash(byte[] content)
        {
            byte[] hashBytes = CreateMd5Hash(content);
            return Convert.ToBase64String(hashBytes);
        }

        /// <summary>
        /// Computes an MD5 hash from a string and returns it as a base64 converted string.
        /// </summary>
        /// <param name="content">The content to hash.</param>
        /// <returns>The hash as a base64 <see cref="string"/>.</returns>
        /// <exception cref="ArgumentNullException">The content is null.</exception>
        /// <exception cref="HmacConfigurationException">One or more of the configuration parameters are invalid.</exception>
        public string CreateBase64Md5Hash(string content)
        {
            byte[] hashBytes = CreateMd5Hash(content);
            return Convert.ToBase64String(hashBytes);
        }

        /// <summary>
        /// Creates a string from a header <see cref="NameValueCollection"/> where the headers are canonicalized.
        /// </summary>
        /// <param name="headers">The collection of headers to canonicalize.</param>
        /// <returns>The canonicalized headers as a single <see cref="string"/>.</returns>
        /// <remarks>
        /// Canonicalization is done by:
        /// - Trimming the whitespace of the header names and converting them to lowercase;
        /// - Normalizing the header values (reducing whitespace sequences to a single space character);
        /// - Merging duplicate headers into one, where the value becomes a comma-separated value list;
        /// - Joining the header name and value, separated by a colon;
        /// - Sorting the canonicalized headers ordinally;
        /// - Joining the canonicalized headers into a single string, separated by the configured signature data separator.
        /// </remarks>
        /// <exception cref="ArgumentNullException">The headers collection is null.</exception>
        public virtual string CreateCanonicalizedHeadersString(NameValueCollection headers)
        {
            if (headers == null)
                throw new ArgumentNullException(nameof(headers), "The header collection cannot be null.");

            List<string> headerList = new List<string>();

            foreach (string key in headers.Keys)
            {
                string headerName = key.Trim().ToLowerInvariant();
                string[] headerValueArray = headers.GetValues(key);
                string headerValues = null;

                if (headerValueArray != null)
                {
                    IEnumerable<string> normalizedHeaderValues = headerValueArray.Select(hv => hv.NormalizeWhiteSpace());
                    headerValues = string.Join(",", normalizedHeaderValues);
                }

                headerList.Add(string.Join(":", headerName, headerValues));
            }

            headerList.Sort(StringComparer.Ordinal);
            return string.Join(HmacConfiguration.SignatureDataSeparator ?? string.Empty, headerList);
        }

        /// <summary>
        /// Adds the HTTP Authorization header with the signature to the request.
        /// </summary>
        /// <param name="request">The request in which to set the authorization.</param>
        /// <param name="signature">The signature to add to the header.</param>
        /// <exception cref="ArgumentNullException">The request is null.</exception>
        /// <exception cref="ArgumentException">The request's header collection is null.</exception>
        /// <exception cref="HmacConfigurationException">One or more of the configuration parameters are invalid.</exception>
        public void AddAuthorizationHeader(HttpRequestMessage request, string signature)
        {
            if (request == null)
                throw new ArgumentNullException(nameof(request), "The request cannot be null.");
            if (request.Headers == null)
                throw new ArgumentException("The request's header collection cannot be null.");
            if (string.IsNullOrEmpty(HmacConfiguration.AuthorizationScheme))
                throw new HmacConfigurationException("The authorization scheme has not been configured.");

            request.Headers.Add(
                HmacConstants.AuthorizationHeaderName,
                string.Format(HmacConstants.AuthorizationHeaderFormat, HmacConfiguration.AuthorizationScheme, signature));
        }

        /// <summary>
        /// Adds the HTTP Authorization header with the signature to the request.
        /// </summary>
        /// <param name="request">The request in which to set the authorization.</param>
        /// <param name="signature">The signature to add to the header.</param>
        /// <exception cref="ArgumentNullException">The request is null.</exception>
        /// <exception cref="ArgumentException">The request's header collection is null.</exception>
        /// <exception cref="HmacConfigurationException">One or more of the configuration parameters are invalid.</exception>
        public void AddAuthorizationHeader(HttpRequestBase request, string signature)
        {
            if (request == null)
                throw new ArgumentNullException(nameof(request), "The request cannot be null.");
            if (request.Headers == null)
                throw new ArgumentException("The request's header collection cannot be null.");
            if (string.IsNullOrEmpty(HmacConfiguration.AuthorizationScheme))
                throw new HmacConfigurationException("The authorization scheme has not been configured.");

            request.Headers.Add(
                HmacConstants.AuthorizationHeaderName,
                string.Format(HmacConstants.AuthorizationHeaderFormat, HmacConfiguration.AuthorizationScheme, signature));
        }

        private HmacSignatureData GetSignatureDataFromHttpRequest(HmacRequestWrapper request)
        {
            HmacSignatureData signatureData = new HmacSignatureData
            {
                HttpMethod = request.Method.ToUpper(),
                RequestUri = request.RequestUri.AbsoluteUri
            };

            // Get the request date
            if (request.Date.HasValue)
            {
                DateTime date = request.Date.Value.UtcDateTime;
                signatureData.Date = date.ToString(HmacConstants.DateHeaderFormat, DateHeaderCulture);
            }

            // Get the content type and MD5 body hash
            signatureData.ContentType = request.ContentType;
            signatureData.ContentMd5 = request.ContentMd5;

            // Get the username
            if (!string.IsNullOrEmpty(HmacConfiguration.UserHeaderName))
            {
                bool hasUserHeader = request.Headers.AllKeys.Contains(HmacConfiguration.UserHeaderName, StringComparer.OrdinalIgnoreCase);
                if (hasUserHeader)
                    signatureData.Username = request.Headers[HmacConfiguration.UserHeaderName];
            }

            // Get the key
            try
            {
                signatureData.Key = HmacKeyRepository.GetHmacKeyForUsername(signatureData.Username);
            }
            catch (Exception ex)
            {
                throw new HmacKeyRepositoryException("Failed to retrieve the key.", ex);
            }

            // Add full additional headers
            if (HmacConfiguration.Headers != null && HmacConfiguration.Headers.Count > 0)
            {
                signatureData.Headers = new NameValueCollection(StringComparer.OrdinalIgnoreCase);

                foreach (string headerName in HmacConfiguration.Headers)
                {
                    if (string.IsNullOrEmpty(headerName))
                        continue;

                    IList<string> headerValues = request.Headers.GetValues(headerName);
                    if (headerValues == null || headerValues.Count == 0)
                        continue;

                    foreach (string headerValue in headerValues)
                        signatureData.Headers.Add(headerName, headerValue);
                }
            }

            return signatureData;
        }
    }
}