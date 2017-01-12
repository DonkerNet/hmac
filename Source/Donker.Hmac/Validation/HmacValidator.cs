using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Web;
using Donker.Hmac.Configuration;
using Donker.Hmac.Helpers;
using Donker.Hmac.Signing;

namespace Donker.Hmac.Validation
{
    /// <summary>
    /// Class for validating HMAC signed requests.
    /// </summary>
    public class HmacValidator : IHmacValidator
    {
        /// <summary>
        /// Gets the instance of the used signer.
        /// </summary>
        protected IHmacSigner HmacSigner { get; }
        /// <summary>
        /// Gets the configuration used for signing and validating requests.
        /// </summary>
        protected IHmacConfiguration HmacConfiguration { get; }
        /// <summary>
        /// Gets the culture information for the value of the HTTP Date header.
        /// </summary>
        protected CultureInfo DateHeaderCulture { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="HmacValidator"/> class using the specified configuration and signer.
        /// </summary>
        /// <param name="configuration">The configuration used for signing and validating.</param>
        /// <param name="signer">The signer to use for creating a signature.</param>
        /// <exception cref="ArgumentNullException">The configuration or signer is null.</exception>
        public HmacValidator(IHmacConfiguration configuration, IHmacSigner signer)
        {
            if (configuration == null)
                throw new ArgumentNullException(nameof(configuration), "The configuration cannot be null.");
            if (signer == null)
                throw new ArgumentNullException(nameof(signer), "The signer cannot be null.");

            HmacConfiguration = configuration;
            HmacSigner = signer;
            DateHeaderCulture = new CultureInfo(HmacConstants.DateHeaderCulture);
        }

        /// <summary>
        /// Validates an entire HTTP request message.
        /// </summary>
        /// <param name="request">The HTTP request to validate.</param>
        /// <returns>The result of the validation as a <see cref="HmacValidationResult"/> object.</returns>
        /// <remarks>
        /// The following validation logic is used:
        /// - The Date header must be present if a maximum request age is configured, but cannot be older than the configured value;
        /// - The username header must be present when the user header name has been configured;
        /// - The key must be found for the request;
        /// - The Authorization header must be present, must have the correct authorization scheme and must contain a signature;
        /// - The signature created from the extracted signature data must match the one on the Authorization header.
        /// 
        /// In case the request contains a body:
        /// - The Content-MD5 header value must match an MD5 hash of the body, if Content-MD5 validation was enabled in the configuration.
        /// </remarks>
        /// <exception cref="ArgumentNullException">The request is null.</exception>
        /// <exception cref="HmacConfigurationException">One or more of the configuration parameters are invalid.</exception>
        public virtual HmacValidationResult ValidateHttpRequest(HttpRequestMessage request)
        {
            if (request == null)
                throw new ArgumentNullException(nameof(request), "The request cannot be null.");

            HmacRequestWrapper requestWrapper = new HmacRequestWrapper(request);
            HmacSignatureData signatureData = HmacSigner.GetSignatureDataFromHttpRequest(request);
            return ValidateHttpRequest(requestWrapper, signatureData);
        }

        /// <summary>
        /// Validates an entire HTTP request.
        /// </summary>
        /// <param name="request">The HTTP request to validate.</param>
        /// <returns>The result of the validation as a <see cref="HmacValidationResult"/> object.</returns>
        /// <remarks>
        /// The following validation logic is used:
        /// - The Date header must be present if a maximum request age is configured, but cannot be older than the configured value;
        /// - The username header must be present when the user header name has been configured;
        /// - The key must be found for the request;
        /// - The Authorization header must be present, must have the correct authorization scheme and must contain a signature;
        /// - The signature created from the extracted signature data must match the one on the Authorization header.
        /// 
        /// In case the request contains a body:
        /// - The Content-MD5 header value must match an MD5 hash of the body, if Content-MD5 validation was enabled in the configuration.
        /// </remarks>
        /// <exception cref="ArgumentNullException">The request is null.</exception>
        /// <exception cref="HmacConfigurationException">One or more of the configuration parameters are invalid.</exception>
        public virtual HmacValidationResult ValidateHttpRequest(HttpRequestBase request)
        {
            if (request == null)
                throw new ArgumentNullException(nameof(request), "The request cannot be null.");

            HmacRequestWrapper requestWrapper = new HmacRequestWrapper(request);
            HmacSignatureData signatureData = HmacSigner.GetSignatureDataFromHttpRequest(request);
            return ValidateHttpRequest(requestWrapper, signatureData);
        }

        /// <summary>
        /// Validates a datetime of a request according to the HMAC configuration that is used.
        /// </summary>
        /// <param name="dateTime">The datetime to validate.</param>
        /// <returns><c>true</c> if valid; otherwise, <c>false</c>.</returns>
        public bool IsValidRequestDate(DateTime dateTime)
        {
            if (!HmacConfiguration.MaxRequestAge.HasValue)
                return true;

            if (dateTime.Kind == DateTimeKind.Local)
                dateTime = dateTime.ToUniversalTime();

            DateTime currentDateTime = DateTime.UtcNow;
            return currentDateTime <= dateTime.Add(HmacConfiguration.MaxRequestAge.Value);
        }

        /// <summary>
        /// Validates a datetime string of a request according to the HMAC configuration that is used.
        /// </summary>
        /// <param name="dateTime">The datetime string to validate.</param>
        /// <param name="format">The format in which the datetime is.</param>
        /// <returns><c>true</c> if valid; otherwise, <c>false</c>.</returns>
        /// <exception cref="ArgumentNullException">The format is null.</exception>
        public bool IsValidRequestDate(string dateTime, string format)
        {
            if (format == null)
                throw new ArgumentNullException(nameof(format), "The format cannot be null.");

            if (string.IsNullOrEmpty(dateTime))
                return false;

            DateTimeOffset parsedDateTime;
            if (DateTimeOffset.TryParseExact(dateTime, HmacConstants.DateHeaderFormat, DateHeaderCulture, DateTimeStyles.AssumeUniversal, out parsedDateTime))
                return IsValidRequestDate(parsedDateTime.UtcDateTime);

            return false;
        }

        /// <summary>
        /// Validates a datetime offset of a request according to the HMAC configuration that is used.
        /// </summary>
        /// <param name="dateTimeOffset">The datetime offset to validate.</param>
        /// <returns><c>true</c> if valid; otherwise, <c>false</c>.</returns>
        public bool IsValidRequestDate(DateTimeOffset dateTimeOffset)
        {
            return IsValidRequestDate(dateTimeOffset.UtcDateTime);
        }

        /// <summary>
        /// MD5 hashes the specified body stream and compares it with the Content-MD5 string.
        /// </summary>
        /// <param name="contentMd5">The Content-MD5 string to compare the body hash to.</param>
        /// <param name="bodyContent">The body to hash and compare.</param>
        /// <returns><c>true</c> if equal; otherwise, <c>false</c>.</returns>
        /// <exception cref="ArgumentException">The body content stream does not support seeking or reading.</exception>
        public bool IsValidContentMd5(string contentMd5, Stream bodyContent)
        {
            if (bodyContent == null)
                return string.IsNullOrEmpty(contentMd5);

            if (!bodyContent.CanSeek)
                throw new ArgumentException("The body content stream does not support seeking.", nameof(bodyContent));
            if (!bodyContent.CanRead)
                throw new ArgumentException("The body content stream does not support reading.", nameof(bodyContent));

            if (string.IsNullOrEmpty(contentMd5))
                return bodyContent.Length == 0;

            string newContentMd5 = HmacSigner.CreateBase64Md5Hash(bodyContent);
            return contentMd5 == newContentMd5;
        }

        /// <summary>
        /// MD5 hashes the specified body stream and compares it with the Content-MD5 hash byte array.
        /// </summary>
        /// <param name="contentMd5">The Content-MD5 hash byte array to compare the body hash to.</param>
        /// <param name="bodyContent">The body to hash and compare.</param>
        /// <returns><c>true</c> if equal; otherwise, <c>false</c>.</returns>
        /// <exception cref="ArgumentException">The body content stream does not support seeking or reading.</exception>
        public bool IsValidContentMd5(byte[] contentMd5, Stream bodyContent)
        {
            string contentMd5String = contentMd5.IsNullOrEmpty() ? null : Convert.ToBase64String(contentMd5);
            return IsValidContentMd5(contentMd5String, bodyContent);
        }

        /// <summary>
        /// MD5 hashes the specified body byte array and compares it with the Content-MD5 string.
        /// </summary>
        /// <param name="contentMd5">The Content-MD5 string to compare the body hash to.</param>
        /// <param name="bodyContent">The body to hash and compare.</param>
        /// <returns><c>true</c> if equal; otherwise, <c>false</c>.</returns>
        public bool IsValidContentMd5(string contentMd5, byte[] bodyContent)
        {
            if (string.IsNullOrEmpty(contentMd5))
                return bodyContent.IsNullOrEmpty();
            if (bodyContent.IsNullOrEmpty())
                return false;

            string newContentMd5 = HmacSigner.CreateBase64Md5Hash(bodyContent);
            return contentMd5 == newContentMd5;
        }

        /// <summary>
        /// MD5 hashes the specified body byte array and compares it with the Content-MD5 hash byte array.
        /// </summary>
        /// <param name="contentMd5">The Content-MD5 hash byte array to compare the body hash to.</param>
        /// <param name="bodyContent">The body to hash and compare.</param>
        /// <returns><c>true</c> if equal; otherwise, <c>false</c>.</returns>
        public bool IsValidContentMd5(byte[] contentMd5, byte[] bodyContent)
        {
            if (contentMd5.IsNullOrEmpty())
                return bodyContent.IsNullOrEmpty();

            string contentMd5String = Convert.ToBase64String(contentMd5);
            return IsValidContentMd5(contentMd5String, bodyContent);
        }

        /// <summary>
        /// MD5 hashes the specified body and compares it with the Content-MD5 string.
        /// </summary>
        /// <param name="contentMd5">The Content-MD5 string to compare the body hash to.</param>
        /// <param name="bodyContent">The body to hash and compare.</param>
        /// <param name="encoding">The encoding to use when converting the body content into bytes.</param>
        /// <returns><c>true</c> if equal; otherwise, <c>false</c>.</returns>
        /// <exception cref="ArgumentNullException">The encoding is null.</exception>
        public bool IsValidContentMd5(string contentMd5, string bodyContent, Encoding encoding)
        {
            if (encoding == null)
                throw new ArgumentNullException(nameof(encoding), "The encoding cannot be null.");

            if (string.IsNullOrEmpty(contentMd5))
                return string.IsNullOrEmpty(bodyContent);

            if (string.IsNullOrEmpty(bodyContent))
                return false;

            string newContentMd5 = HmacSigner.CreateBase64Md5Hash(bodyContent, encoding);
            return contentMd5 == newContentMd5;
        }

        /// <summary>
        /// MD5 hashes the specified body and compares it with the Content-MD5 hash byte array.
        /// </summary>
        /// <param name="contentMd5">The Content-MD5 hash byte array to compare the body hash to.</param>
        /// <param name="bodyContent">The body to hash and compare.</param>
        /// <param name="encoding">The encoding to use when converting the body content into bytes.</param>
        /// <returns><c>true</c> if equal; otherwise, <c>false</c>.</returns>
        /// <exception cref="ArgumentNullException">The encoding is null.</exception>
        public bool IsValidContentMd5(byte[] contentMd5, string bodyContent, Encoding encoding)
        {
            if (contentMd5.IsNullOrEmpty())
                return string.IsNullOrEmpty(bodyContent);

            string contentMd5String = Convert.ToBase64String(contentMd5);
            return IsValidContentMd5(contentMd5String, bodyContent, encoding);
        }

        /// <summary>
        /// Compares two signatures.
        /// </summary>
        /// <param name="first">The first signature to compare.</param>
        /// <param name="second">The second signature to compare.</param>
        /// <returns><c>true</c> if equal; otherwise, <c>false</c>.</returns>
        public bool IsValidSignature(string first, string second)
        {
            if (string.IsNullOrEmpty(first))
                return string.IsNullOrEmpty(second);

            return Equals(first, second);
        }

        /// <summary>
        /// Compares two signatures.
        /// </summary>
        /// <param name="first">The first signature to compare.</param>
        /// <param name="second">The second signature to compare.</param>
        /// <returns><c>true</c> if equal; otherwise, <c>false</c>.</returns>
        public bool IsValidSignature(byte[] first, byte[] second)
        {
            if (first == null)
                return second == null;
            if (second == null)
                return false;

            return first.SequenceEqual(second);
        }

        /// <summary>
        /// Adds an HTTP WWW-Authenticate header to the response.
        /// </summary>
        /// <param name="response">The response in which to set the header.</param>
        /// <param name="value">The value to add to the header.</param>
        /// <exception cref="ArgumentNullException">The response is null.</exception>
        /// <exception cref="ArgumentException">The response's header collection is null.</exception>
        public void AddWwwAuthenticateHeader(HttpResponseMessage response, string value)
        {
            if (response == null)
                throw new ArgumentNullException(nameof(response), "The response cannot be null.");
            if (response.Headers == null)
                throw new ArgumentException("The response's header collection cannot be null.");

            response.Headers.Add(HmacConstants.WwwAuthenticateHeaderName, value);
        }

        /// <summary>
        /// Adds an HTTP WWW-Authenticate header to the response.
        /// </summary>
        /// <param name="response">The response in which to set the header.</param>
        /// <param name="value">The value to add to the header.</param>
        /// <exception cref="ArgumentNullException">The response is null.</exception>
        /// <exception cref="ArgumentException">The response's header collection is null.</exception>
        public void AddWwwAuthenticateHeader(HttpResponseBase response, string value)
        {
            if (response == null)
                throw new ArgumentNullException(nameof(response), "The response cannot be null.");
            if (response.Headers == null)
                throw new ArgumentException("The response's header collection cannot be null.");

            response.Headers.Add(HmacConstants.WwwAuthenticateHeaderName, value);
        }

        private HmacValidationResult ValidateHttpRequest(HmacRequestWrapper request, HmacSignatureData signatureData)
        {
            if (string.IsNullOrEmpty(HmacConfiguration.AuthorizationScheme))
                throw new HmacConfigurationException("The AuthorizationScheme cannot be null or empty.");

            // Note: the Content-MD5 and Content-Type headers are only required if the request contains a body

            // If configured, the request date is validated to prevent replay attacks
            if (HmacConfiguration.MaxRequestAge.HasValue)
            {
                if(!request.Date.HasValue)
                    return new HmacValidationResult(HmacValidationResultCode.DateMissing, "The request date was not found.");
                if (!IsValidRequestDate(request.Date.Value))
                    return new HmacValidationResult(HmacValidationResultCode.DateInvalid, "The request date is invalid.");
            }

            // The username is always required when the header has been configured
            if (!string.IsNullOrEmpty(HmacConfiguration.UserHeaderName) && string.IsNullOrEmpty(signatureData.Username))
                return new HmacValidationResult(HmacValidationResultCode.UsernameMissing, "The username is required but was not found.");

            // The key must be found
            if (string.IsNullOrEmpty(signatureData.Key))
                return new HmacValidationResult(HmacValidationResultCode.KeyMissing, "The key was not found.");

            // If configured, an MD5 hash of the body is generated and compared with the Content-MD5 header value to check if the body hasn't been altered
            if (HmacConfiguration.ValidateContentMd5 && !IsValidContentMd5(signatureData.ContentMd5, request.Content))
            {
                if (string.IsNullOrEmpty(signatureData.ContentMd5))
                    return new HmacValidationResult(HmacValidationResultCode.BodyHashMissing, "The MD5 body hash was not found.");
                return new HmacValidationResult(HmacValidationResultCode.BodyHashMismatch, "The body content differs.");
            }

            // The Authorization header is always required and should contain the scheme and signature

            IList<string> authorizations = request.Headers.GetValues(HmacConstants.AuthorizationHeaderName);
            string authorization;

            if (authorizations == null || string.IsNullOrEmpty(authorization = authorizations.FirstOrDefault()))
                return new HmacValidationResult(HmacValidationResultCode.AuthorizationMissing, "The signature was not found.");

            string[] authorizationParts = authorization.Split(' ');

            if (authorizationParts.Length < 2 || authorizationParts[0] != HmacConfiguration.AuthorizationScheme)
                return new HmacValidationResult(HmacValidationResultCode.AuthorizationInvalid, "The signature was not correctly specified.");

            // Finally, the signature from the Authorization header should match the newly created signature

            string signature = authorizationParts[1];

            string newSignature = HmacSigner.CreateSignature(signatureData);

            if (!IsValidSignature(signature, newSignature))
                return new HmacValidationResult(HmacValidationResultCode.SignatureMismatch, "The signature does not match.");

            return HmacValidationResult.Ok;
        }
    }
}