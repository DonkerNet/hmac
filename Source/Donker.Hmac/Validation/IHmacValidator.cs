using System;
using System.IO;
using System.Net.Http;
using System.Text;
using System.Web;

namespace Donker.Hmac.Validation
{
    /// <summary>
    /// Interface for classes that validate HMAC signed requests.
    /// </summary>
    public interface IHmacValidator
    {
        /// <summary>
        /// Validates an entire HTTP request message.
        /// </summary>
        /// <param name="request">The HTTP request message to validate.</param>
        /// <returns>The result of the validation as a <see cref="HmacValidationResult"/> object.</returns>
        HmacValidationResult ValidateHttpRequest(HttpRequestMessage request);
        /// <summary>
        /// Validates an entire HTTP request.
        /// </summary>
        /// <param name="request">The HTTP request to validate.</param>
        /// <returns>The result of the validation as a <see cref="HmacValidationResult"/> object.</returns>
        HmacValidationResult ValidateHttpRequest(HttpRequestBase request);
        /// <summary>
        /// Validates a datetime of a request according to the HMAC configuration that is used.
        /// </summary>
        /// <param name="dateTime">The datetime to validate.</param>
        /// <returns><c>true</c> if valid; otherwise, <c>false</c>.</returns>
        bool IsValidRequestDate(DateTime dateTime);
        /// <summary>
        /// Validates a datetime string of a request according to the HMAC configuration that is used.
        /// </summary>
        /// <param name="dateTime">The datetime string to validate.</param>
        /// <param name="format">The format in which the datetime is.</param>
        /// <returns><c>true</c> if valid; otherwise, <c>false</c>.</returns>
        bool IsValidRequestDate(string dateTime, string format);
        /// <summary>
        /// Validates a datetime offset of a request according to the HMAC configuration that is used.
        /// </summary>
        /// <param name="dateTimeOffset">The datetime offset to validate.</param>
        /// <returns><c>true</c> if valid; otherwise, <c>false</c>.</returns>
        bool IsValidRequestDate(DateTimeOffset dateTimeOffset);
        /// <summary>
        /// MD5 hashes the specified body stream and compares it with the Content-MD5 string.
        /// </summary>
        /// <param name="contentMd5">The Content-MD5 string to compare the body hash to.</param>
        /// <param name="bodyContent">The body to hash and compare.</param>
        /// <returns><c>true</c> if equal; otherwise, <c>false</c>.</returns>
        bool IsValidContentMd5(string contentMd5, Stream bodyContent);
        /// <summary>
        /// MD5 hashes the specified body stream and compares it with the Content-MD5 hash byte array.
        /// </summary>
        /// <param name="contentMd5">The Content-MD5 hash byte array to compare the body hash to.</param>
        /// <param name="bodyContent">The body to hash and compare.</param>
        /// <returns><c>true</c> if equal; otherwise, <c>false</c>.</returns>
        bool IsValidContentMd5(byte[] contentMd5, Stream bodyContent);
        /// <summary>
        /// MD5 hashes the specified body byte array and compares it with the Content-MD5 string.
        /// </summary>
        /// <param name="contentMd5">The Content-MD5 string to compare the body hash to.</param>
        /// <param name="bodyContent">The body to hash and compare.</param>
        /// <returns><c>true</c> if equal; otherwise, <c>false</c>.</returns>
        bool IsValidContentMd5(string contentMd5, byte[] bodyContent);
        /// <summary>
        /// MD5 hashes the specified body byte array and compares it with the Content-MD5 hash byte array.
        /// </summary>
        /// <param name="contentMd5">The Content-MD5 hash byte array to compare the body hash to.</param>
        /// <param name="bodyContent">The body to hash and compare.</param>
        /// <returns><c>true</c> if equal; otherwise, <c>false</c>.</returns>
        bool IsValidContentMd5(byte[] contentMd5, byte[] bodyContent);
        /// <summary>
        /// MD5 hashes the specified body and compares it with the Content-MD5 string.
        /// </summary>
        /// <param name="contentMd5">The Content-MD5 string to compare the body hash to.</param>
        /// <param name="bodyContent">The body to hash to compare.</param>
        /// <param name="encoding">The encoding to use when converting the body content into bytes.</param>
        /// <returns><c>true</c> if equal; otherwise, <c>false</c>.</returns>
        bool IsValidContentMd5(string contentMd5, string bodyContent, Encoding encoding);
        /// <summary>
        /// MD5 hashes the specified body and compares it with the Content-MD5 hash byte array.
        /// </summary>
        /// <param name="contentMd5">The Content-MD5 hash byte array to compare the body hash to.</param>
        /// <param name="bodyContent">The body to hash to compare.</param>
        /// <param name="encoding">The encoding to use when converting the body content into bytes.</param>
        /// <returns><c>true</c> if equal; otherwise, <c>false</c>.</returns>
        bool IsValidContentMd5(byte[] contentMd5, string bodyContent, Encoding encoding);
        /// <summary>
        /// Compares two signatures in their string representation.
        /// </summary>
        /// <param name="first">The first signature string to compare.</param>
        /// <param name="second">The second signature string to compare.</param>
        /// <returns><c>true</c> if equal; otherwise, <c>false</c>.</returns>
        bool IsValidSignature(string first, string second);
        /// <summary>
        /// Compares two signatures.
        /// </summary>
        /// <param name="first">The first signature to compare.</param>
        /// <param name="second">The second signature to compare.</param>
        /// <returns><c>true</c> if equal; otherwise, <c>false</c>.</returns>
        bool IsValidSignature(byte[] first, byte[] second);
        /// <summary>
        /// Adds an HTTP WWW-Authenticate header to the response.
        /// </summary>
        /// <param name="response">The response in which to set the header.</param>
        /// <param name="value">The value to add to the header.</param>
        void AddWwwAuthenticateHeader(HttpResponseMessage response, string value);
        /// <summary>
        /// Adds an HTTP WWW-Authenticate header to the response.
        /// </summary>
        /// <param name="response">The response in which to set the header.</param>
        /// <param name="value">The value to add to the header.</param>
        void AddWwwAuthenticateHeader(HttpResponseBase response, string value);
    }
}