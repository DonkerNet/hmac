using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Donker.Hmac.Configuration;
using Donker.Hmac.RestSharp.Authenticators;
using Donker.Hmac.RestSharp.Signing;
using Donker.Hmac.Signing;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using RestSharp;

namespace Donker.Hmac.RestSharp.Test
{
    [TestClass]
    public class HmacAuthenticatorTests
    {
        private const string Body = "{\"Example\":\"Value\"}";
        private const string Url = "http://www.example.website/test.json";
        private const string ContentType = "application/json";

        private SingleUserHmacKeyRepository _keyRepository;
        private string _base64Md5Hash;
        private CultureInfo _dateHeaderCulture;

        [TestInitialize]
        public void Initialize()
        {
            _keyRepository = new SingleUserHmacKeyRepository("TestUser", "TestKey");
            _base64Md5Hash = Convert.ToBase64String(MD5.Create().ComputeHash(Encoding.UTF8.GetBytes(Body)));
            _dateHeaderCulture = CultureInfo.GetCultureInfo(HmacConstants.DateHeaderCulture);
        }

        [TestMethod]
        public void ShouldAuthenticate()
        {
            // Arrange
            IHmacConfiguration configuration = CreateConfiguration();
            IRestSharpHmacSigner signer = new RestSharpHmacSigner(configuration, _keyRepository);
            HmacAuthenticator authenticator = new HmacAuthenticator(configuration, signer);
            IRestClient client = CreateClient();
            IRestRequest request = CreateRequest(configuration);
            
            // Act
            authenticator.Authenticate(client, request);
            var contentMd5Param = request.Parameters.FirstOrDefault(p => p.Name == "Content-MD5");
            var authorizationParam = request.Parameters.FirstOrDefault(p => p.Name == "Authorization");
            var dateParam = request.Parameters.FirstOrDefault(p => p.Name == "Date");
            string dateString = dateParam != null ? dateParam.Value as string ?? string.Empty : string.Empty;
            DateTimeOffset parsedDate;
            bool isValidDate = DateTimeOffset.TryParseExact(dateString, "ddd, dd MMM yyyy HH:mm:ss G\\MT", _dateHeaderCulture, DateTimeStyles.AssumeUniversal, out parsedDate);
            HmacSignatureData signatureData = signer.GetSignatureDataFromRestRequest(client, request);
            string signature = signer.CreateSignature(signatureData);

            // Assert
            Assert.IsNotNull(contentMd5Param);
            Assert.AreEqual(ParameterType.HttpHeader, contentMd5Param.Type);
            Assert.AreEqual(_base64Md5Hash, contentMd5Param.Value);
            Assert.IsNotNull(authorizationParam);
            Assert.AreEqual(ParameterType.HttpHeader, authorizationParam.Type);
            Assert.IsNotNull(authorizationParam.Value);
            Assert.IsInstanceOfType(authorizationParam.Value, typeof(string));
            Assert.AreEqual((string)authorizationParam.Value, "HMAC " + signature);
            Assert.IsNotNull(dateParam);
            Assert.AreEqual(ParameterType.HttpHeader, dateParam.Type);
            Assert.IsNotNull(dateParam.Value);
            Assert.IsTrue(isValidDate);
        }

        private HmacConfiguration CreateConfiguration()
        {
            return new HmacConfiguration
            {
                UserHeaderName = "X-Auth-User",
                AuthorizationScheme = "HMAC",
                SignatureDataSeparator = "\n",
                SignatureEncoding = "UTF-8",
                HmacAlgorithm = "HMACSHA512",
                MaxRequestAge = TimeSpan.FromMinutes(5),
                SignRequestUri = true,
                ValidateContentMd5 = true,
                Headers = new List<string> { "X-Custom-Test-Header-1", "X-Custom-Test-Header-2" }
            };
        }

        private IRestRequest CreateRequest(IHmacConfiguration configuration)
        {
#pragma warning disable CS0618 // Obsolete warning for Parameter
            List<Parameter> parameters = new List<Parameter>
            {
                new Parameter(string.Empty, Body, ContentType, ParameterType.RequestBody),
                new Parameter(configuration.UserHeaderName, _keyRepository.Username, ParameterType.HttpHeader),
                new Parameter("X-Custom-Test-Header-1", "Test1", ParameterType.HttpHeader),
                new Parameter("X-Custom-Test-Header-2", "Test2", ParameterType.HttpHeader)
            };
#pragma warning restore CS0618 // Obsolete warning for Parameter

#pragma warning disable CS0618 // Obsolete warning for RequestBody
            RequestBody body = new RequestBody(ContentType, string.Empty, Body);
#pragma warning restore CS0618 // Obsolete warning for RequestBody

            Mock<IRestRequest> mockRequest = new Mock<IRestRequest>();
            mockRequest.Setup(r => r.Method).Returns(Method.POST);
            mockRequest.Setup(r => r.Parameters).Returns(parameters);
            mockRequest.Setup(r => r.Body).Returns(body);
            mockRequest
                .Setup(r => r.AddParameter(It.IsAny<string>(), It.IsAny<object>(), It.IsAny<ParameterType>()))
#pragma warning disable CS0618 // Obsolete warning for Parameter
                .Callback((string name, object value, ParameterType type) => parameters.Add(new Parameter(name, value, type)));
#pragma warning restore CS0618 // Obsolete warning for Parameter
            return mockRequest.Object;
        }

        private IRestClient CreateClient()
        {
            Mock<IRestClient> mockClient = new Mock<IRestClient>();
#pragma warning disable CS0618 // Obsolete warning for Parameter
            mockClient.Setup(c => c.DefaultParameters).Returns(new List<Parameter>());
#pragma warning restore CS0618 // Obsolete warning for Parameter
            mockClient.Setup(c => c.BuildUri(It.IsAny<IRestRequest>())).Returns(new Uri(Url));
            return mockClient.Object;
        }
    }
}