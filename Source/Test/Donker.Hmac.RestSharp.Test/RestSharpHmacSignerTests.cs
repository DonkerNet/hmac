using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Donker.Hmac.Configuration;
using Donker.Hmac.RestSharp.Signing;
using Donker.Hmac.Signing;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using RestSharp;

namespace Donker.Hmac.RestSharp.Test
{
    [TestClass]
    public class RestSharpHmacSignerTests
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
        public void ShouldGetSignatureDataFromRestRequest()
        {
            // Arrange
            IHmacConfiguration configuration = CreateConfiguration();
            string dateString = CreateHttpDateString();
            IRestClient client = CreateClient();
            IRestRequest request = CreateRequest(configuration, dateString);
            RestSharpHmacSigner signer = new RestSharpHmacSigner(configuration, _keyRepository);

            // Act
            HmacSignatureData signatureData = signer.GetSignatureDataFromRestRequest(client, request);

            // Assert
            Assert.IsNotNull(signatureData);
            Assert.AreEqual(_keyRepository.Key, signatureData.Key);
            Assert.AreEqual(request.Method.ToString().ToUpperInvariant(), signatureData.HttpMethod);
            Assert.AreEqual(_base64Md5Hash, signatureData.ContentMd5);
            Assert.AreEqual(ContentType, signatureData.ContentType);
            Assert.AreEqual(dateString, signatureData.Date);
            Assert.AreEqual(_keyRepository.Username, signatureData.Username);
            Assert.AreEqual(Url, signatureData.RequestUri);
            Assert.IsNotNull(signatureData.Headers);
            Assert.IsTrue(signatureData.Headers.Count > 0);
        }

        [TestMethod]
        public void ShouldAddAuthorizationHeader()
        {
            // Arrange
            const string signature = "TEST_SIGNATURE";
            IHmacConfiguration configuration = CreateConfiguration();
            IRestRequest request = CreateRequest(configuration, string.Empty);
            RestSharpHmacSigner signer = new RestSharpHmacSigner(configuration, _keyRepository);

            // Act
            signer.AddAuthorizationHeader(request, signature);
            Parameter param = request.Parameters.FirstOrDefault(p => p.Name == "Authorization");

            // Assert
            Assert.IsNotNull(param);
            Assert.AreEqual($"{configuration.AuthorizationScheme} {signature}", param.Value);
            Assert.AreEqual(ParameterType.HttpHeader, param.Type);
        }

        private IHmacConfiguration CreateConfiguration()
        {
            return new HmacConfiguration
            {
                UserHeaderName = "X-Auth-User",
                AuthorizationScheme = "HMAC",
                SignatureDataSeparator = "\n",
                SignatureEncoding = Encoding.UTF8,
                HmacAlgorithm = "HMACSHA512",
                MaxRequestAge = TimeSpan.FromMinutes(5),
                SignRequestUri = true,
                ValidateContentMd5 = true,
                Headers = new List<string> { "X-Custom-Test-Header-1", "X-Custom-Test-Header-2" }
            };
        }

        private IRestRequest CreateRequest(IHmacConfiguration configuration, string dateString)
        {
            List<Parameter> parameters = new List<Parameter>
            {
                new Parameter { Name = HmacConstants.DateHeaderName, Value = dateString, Type = ParameterType.HttpHeader },
                new Parameter { Name = ContentType, Value = Body, Type = ParameterType.RequestBody },
                new Parameter { Name = HmacConstants.ContentMd5HeaderName, Value = _base64Md5Hash, Type = ParameterType.HttpHeader },
                new Parameter { Name = configuration.UserHeaderName, Value = _keyRepository.Username, Type = ParameterType.HttpHeader },
                new Parameter { Name = "X-Custom-Test-Header-1", Value = "Test1", Type = ParameterType.HttpHeader },
                new Parameter { Name = "X-Custom-Test-Header-2", Value = "Test2", Type = ParameterType.HttpHeader }
            };
            
            Mock<IRestRequest> mockRequest = new Mock<IRestRequest>();
            mockRequest.Setup(r => r.Method).Returns(Method.POST);
            mockRequest.Setup(r => r.Parameters).Returns(parameters);
            mockRequest
                .Setup(r => r.AddParameter(It.IsAny<string>(), It.IsAny<object>(), It.IsAny<ParameterType>()))
                .Callback((string name, object value, ParameterType type) => parameters.Add(new Parameter { Name = name, Value = value, Type = type }));
            return mockRequest.Object;
        }

        private IRestClient CreateClient()
        {
            Mock<IRestClient> mockClient = new Mock<IRestClient>();
            mockClient.Setup(c => c.DefaultParameters).Returns(new List<Parameter>());
            mockClient.Setup(c => c.BuildUri(It.IsAny<IRestRequest>())).Returns(new Uri(Url));
            return mockClient.Object;
        }

        private string CreateHttpDateString() => DateTime.UtcNow.ToString(HmacConstants.DateHeaderFormat, _dateHeaderCulture);
    }
}