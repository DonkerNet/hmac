using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Linq;
using Donker.Hmac.Configuration;
using Donker.Hmac.RestSharp.Helpers;
using Donker.Hmac.Signing;
using RestSharp;

namespace Donker.Hmac.RestSharp.Signing
{
    /// <summary>
    /// This class allows for the creation of signatures for an HTTP request using RestSharp.
    /// </summary>
    public class RestSharpHmacSigner : HmacSigner, IRestSharpHmacSigner
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="RestSharpHmacSigner"/> class using the specified configuration and key repository.
        /// </summary>
        /// <param name="configuration">The configuration used for signing.</param>
        /// <param name="keyRepository">The repository used for retrieving the key associated with the user.</param>
        /// <exception cref="ArgumentNullException">The configuration or key repository is null.</exception>
        public RestSharpHmacSigner(IHmacConfiguration configuration, IHmacKeyRepository keyRepository)
            : base(configuration, keyRepository)
        {
        }

        /// <summary>
        /// Gets all required signature data, if found, from the RestSharp client or request.
        /// </summary>
        /// <param name="client">The client to get the data from.</param>
        /// <param name="request">The request to get the data from.</param>
        /// <returns>The extracted data as an <see cref="HmacSignatureData"/> object.</returns>
        /// <remarks>
        /// Note 1:
        /// The headers of the client are inspected before those of the request.
        /// Therefore, if a header is both in the client and request, the one from the client will be used.
        /// In case of the body, it's the other way around.
        /// 
        /// Note 2:
        /// The Content-Type is extracted from the body parameter (from the <see cref="Parameter.Name"/> property), NOT from a header parameter.
        /// 
        /// Note 3:
        /// Keep in mind that when signing additional canonicalized headers, some will possibly not be available for signing, which may cause validation to fail.
        /// This is because RestSharps itself adds some headers after authentication and immediately before sending the request (the 'User-Agent' header for example).
        /// </remarks>
        /// <exception cref="ArgumentNullException">The client or request is null.</exception>
        public virtual HmacSignatureData GetSignatureDataFromRestRequest(IRestClient client, IRestRequest request)
        {
            if (client == null)
                throw new ArgumentNullException(nameof(client), "The client cannot be null.");
            if (request == null)
                throw new ArgumentNullException(nameof(request), "The request cannot be null.");

            HmacSignatureData signatureData = new HmacSignatureData
            {
                HttpMethod = request.Method.ToString().ToUpperInvariant()
            };

            // Get the request URI if configured
            if (HmacConfiguration.SignRequestUri)
                signatureData.RequestUri = client.BuildUri(request).AbsoluteUri;

            // Get date if a maximum request age is configured
            if (HmacConfiguration.MaxRequestAge.HasValue)
            {
                var dateParameter = client.DefaultParameters.GetHeaderParameter(HmacConstants.DateHeaderName, request.Parameters);
                if (dateParameter?.Value != null)
                    signatureData.Date = dateParameter.Value.ToString();
            }

            // Get content type
            if (request.Body != null)
            {
                signatureData.ContentType = request.Body.ContentType;

                // Get content MD5 if configured
                if (HmacConfiguration.ValidateContentMd5)
                {
                    var contentMd5Parameter = client.DefaultParameters.GetHeaderParameter(HmacConstants.ContentMd5HeaderName, request.Parameters);
                    if (contentMd5Parameter?.Value != null)
                        signatureData.ContentMd5 = contentMd5Parameter.Value.ToString();
                }
            }

            // Get username
            var usernameParameter = client.DefaultParameters.GetHeaderParameter(HmacConfiguration.UserHeaderName, request.Parameters);
            if (usernameParameter?.Value != null)
                signatureData.Username = usernameParameter.Value.ToString();

            // Get the key
            try
            {
                signatureData.Key = HmacKeyRepository.GetHmacKeyForUsername(signatureData.Username);
            }
            catch (Exception ex)
            {
                throw new HmacKeyRepositoryException("Failed to retrieve the key.", ex);
            }

            // Add additional headers
            if (HmacConfiguration.Headers != null && HmacConfiguration.Headers.Count > 0)
            {
                signatureData.Headers = new NameValueCollection();

                foreach (string headerName in HmacConfiguration.Headers.Distinct(StringComparer.OrdinalIgnoreCase))
                {
                    IEnumerable<string> headerValues;

                    if (!client.DefaultParameters.TryGetHeaderValues(headerName, out headerValues, request.Parameters))
                        continue;

                    foreach (string headerValue in headerValues)
                        signatureData.Headers.Add(headerName, headerValue);
                }
            }

            return signatureData;
        }

        /// <summary>
        /// Adds the HTTP Authorization header with the signature to the request.
        /// </summary>
        /// <param name="request">The request in which to set the authorization.</param>
        /// <param name="signature">The signature to add to the header.</param>
        /// <exception cref="ArgumentNullException">The request is null.</exception>
        public virtual void AddAuthorizationHeader(IRestRequest request, string signature)
        {
            if (request == null)
                throw new ArgumentNullException(nameof(request), "The request cannot be null.");

            // Remove all existing Authorization headers first, just to be sure
            request.Parameters.RemoveAll(p => p.Type == ParameterType.HttpHeader && p.Name == HmacConstants.AuthorizationHeaderName);

            request.AddParameter(
                HmacConstants.AuthorizationHeaderName,
                string.Format(HmacConstants.AuthorizationHeaderFormat, HmacConfiguration.AuthorizationScheme, signature),
                ParameterType.HttpHeader);
        }
    }
}
