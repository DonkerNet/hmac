using Donker.Hmac.Signing;
using RestSharp;

namespace Donker.Hmac.RestSharp.Signing
{
    /// <summary>
    /// Interface for classes that sign RestSharp requests using HMAC.
    /// </summary>
    public interface IRestSharpHmacSigner : IHmacSigner
    {
        /// <summary>
        /// Gets all required signature data, if found, from the RestSharp client or request.
        /// </summary>
        /// <param name="client">The client to get the data from.</param>
        /// <param name="request">The request to get the data from.</param>
        /// <returns>The extracted data as an <see cref="HmacSignatureData"/> object.</returns>
        HmacSignatureData GetSignatureDataFromRestRequest(IRestClient client, IRestRequest request);

        /// <summary>
        /// Adds the HTTP Authorization header with the signature to the request.
        /// </summary>
        /// <param name="request">The request in which to set the authorization.</param>
        /// <param name="signature">The signature to add to the header.</param>
        void AddAuthorizationHeader(IRestRequest request, string signature);
    }
}