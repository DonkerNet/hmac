using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Web;
using Donker.Hmac.Configuration;
using Donker.Hmac.Signing;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;

namespace Donker.Hmac.Test
{
    [TestClass]
    public class HmacSignerTests
    {
        private const string Body = "{\"Example\":\"Value\"}";
        private const string Url = "http://www.example.website/test.json";
        private const string ContentType = "application/json";

        private SingleUserHmacKeyRepository _keyRepository;
        private byte[] _bodyBytes;
        private Stream _bodyStream;
        private byte[] _md5Hash;
        private string _base64Md5Hash;
        private CultureInfo _dateHeaderCulture;

        [TestInitialize]
        public void Initialize()
        {
            _keyRepository = new SingleUserHmacKeyRepository("TestUser", "TestKey");
            _bodyBytes = Encoding.UTF8.GetBytes(Body);
            _bodyStream = new MemoryStream(_bodyBytes);
            _md5Hash = MD5.Create().ComputeHash(_bodyBytes);
            _base64Md5Hash = Convert.ToBase64String(_md5Hash);
            _dateHeaderCulture = CultureInfo.GetCultureInfo(HmacConstants.DateHeaderCulture);
        }

        [TestCleanup]
        public void Cleanup()
        {
            _bodyStream.Dispose();
        }

        [TestMethod]
        public void ShouldGetSignatureDataFromHttpRequest()
        {
            // Arrange
            IHmacConfiguration configuration = CreateConfiguration();
            string dateString = CreateHttpDateString();
            HttpRequestBase request = CreateRequest(dateString);
            HmacSigner signer = new HmacSigner(configuration, _keyRepository);

            // Act
            HmacSignatureData signatureData = signer.GetSignatureDataFromHttpRequest(request);

            // Assert
            Assert.IsNotNull(signatureData);
            Assert.AreEqual(_keyRepository.Key, signatureData.Key);
            Assert.AreEqual(request.HttpMethod, signatureData.HttpMethod);
            Assert.AreEqual(_base64Md5Hash, signatureData.ContentMd5);
            Assert.AreEqual(ContentType, signatureData.ContentType);
            Assert.AreEqual(dateString, signatureData.Date);
            Assert.AreEqual(_keyRepository.Username, signatureData.Username);
            Assert.AreEqual(Url, signatureData.RequestUri);
            Assert.IsNotNull(signatureData.Headers);
            Assert.IsTrue(signatureData.Headers.Count > 0);
        }

        [TestMethod]
        public void ShouldCreateSignature()
        {
            // Arrange
            IHmacConfiguration configuration = CreateConfiguration();
            HmacSigner signer = new HmacSigner(configuration, _keyRepository);
            HmacSignatureData signatureData = new HmacSignatureData
            {
                Key = _keyRepository.Key,
                HttpMethod = "POST",
                ContentMd5 = _base64Md5Hash,
                ContentType = ContentType,
                Date = "Wed, 30 Dec 2015 12:30:45 GMT",
                Username = _keyRepository.Username,
                RequestUri = Url,
                Headers = new NameValueCollection {{"X-Custom-Test-Header-1", "Test1"}, {"X-Custom-Test-Header-2", "Test2"}}
            };
            const string expectedSignature = "ZNIcDaGKZE45U24feUeaO6pZ9e7K/E1IDBf5/uktt8A3Y4Rl6nle9h0KxP1IRJGBiFZjMegci1Ya58prv/vH6Q==";

            // Act
            string signature = signer.CreateSignature(signatureData);

            // Assert
            Assert.IsNotNull(signature);
            Assert.AreEqual(expectedSignature, signature);
        }

        [TestMethod]
        public void ShouldCreateMd5Hash()
        {
            // Arrange
            IHmacConfiguration configuration = new HmacConfiguration { SignatureEncoding = Encoding.UTF8 };
            HmacSigner signer = new HmacSigner(configuration, _keyRepository);

            // Act
            byte[] md5HashFromString = signer.CreateMd5Hash(Body, Encoding.UTF8);
            byte[] md5HashFromBytes = signer.CreateMd5Hash(_bodyBytes);
            byte[] md5HashFromStrean = signer.CreateMd5Hash(_bodyStream);

            // Assert
            Assert.IsNotNull(md5HashFromString);
            Assert.AreEqual(_md5Hash.Length, md5HashFromString.Length);
            Assert.IsTrue(_md5Hash.SequenceEqual(md5HashFromString));
            Assert.IsNotNull(md5HashFromBytes);
            Assert.AreEqual(_md5Hash.Length, md5HashFromBytes.Length);
            Assert.IsTrue(_md5Hash.SequenceEqual(md5HashFromBytes));
            Assert.IsNotNull(md5HashFromStrean);
            Assert.AreEqual(_md5Hash.Length, md5HashFromStrean.Length);
            Assert.IsTrue(_md5Hash.SequenceEqual(md5HashFromStrean));
        }

        [TestMethod]
        public void ShouldCreateBase64Md5Hash()
        {
            // Arrange
            IHmacConfiguration configuration = new HmacConfiguration { SignatureEncoding = Encoding.UTF8 };
            HmacSigner signer = new HmacSigner(configuration, _keyRepository);

            // Act
            string base64Md5HashFromString = signer.CreateBase64Md5Hash(Body, Encoding.UTF8);
            string base64Md5HashFromBytes = signer.CreateBase64Md5Hash(_bodyBytes);
            string base64Md5HashFromStream = signer.CreateBase64Md5Hash(_bodyStream);

            // Assert
            Assert.IsNotNull(base64Md5HashFromString);
            Assert.AreEqual(_base64Md5Hash, base64Md5HashFromString);
            Assert.IsNotNull(base64Md5HashFromBytes);
            Assert.AreEqual(_base64Md5Hash, base64Md5HashFromBytes);
            Assert.IsNotNull(base64Md5HashFromStream);
            Assert.AreEqual(_base64Md5Hash, base64Md5HashFromStream);
        }

        [TestMethod]
        public void ShouldCreateCanonicalizedHeaderString()
        {
            // Arrange
            IHmacConfiguration configuration = new HmacConfiguration { SignatureDataSeparator = "\n" };
            HmacSigner signer = new HmacSigner(configuration, _keyRepository);
            NameValueCollection headers = new NameValueCollection
            {
                {"  X-Test-Header-1 ", " Value2 "},
                {"  X-Test-Header-1 ", " Value4"},
                {"X-Test-Header-2", "value3"},
                {"  x-test-headeR-1 ", "Value1"}
            };
            const string expectedHeaderString = "x-test-header-1:Value2,Value4,Value1\nx-test-header-2:value3";

            // Act
            string headerString = signer.CreateCanonicalizedHeadersString(headers);

            // Assert
            Assert.IsNotNull(headerString);
            Assert.AreEqual(expectedHeaderString, headerString);
        }

        [TestMethod]
        public void ShouldAddAuthorizationHeader()
        {
            // Arrange
            const string signature = "TEST_SIGNATURE";
            IHmacConfiguration configuration = CreateConfiguration();
            HttpRequestBase request = CreateRequest(string.Empty);
            HmacSigner signer = new HmacSigner(configuration, _keyRepository);

            // Act
            signer.AddAuthorizationHeader(request, signature);
            string headerValue = request.Headers["Authorization"];

            // Assert
            Assert.IsNotNull(headerValue);
            Assert.AreEqual("HMAC TEST_SIGNATURE", headerValue);
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

        private HttpRequestBase CreateRequest(string dateString)
        {
            NameValueCollection headers = new NameValueCollection
            {
                [HmacConstants.ContentMd5HeaderName] = _base64Md5Hash,
                [HmacConstants.DateHeaderName] = dateString,
                ["X-Auth-User"] = _keyRepository.Username,
                ["X-Custom-Test-Header-1"] = "Test1",
                ["X-Custom-Test-Header-2"] = "Test2"
            };

            Mock<HttpRequestBase> mockRequest = new Mock<HttpRequestBase>();
            mockRequest.Setup(r => r.InputStream).Returns(_bodyStream);
            mockRequest.Setup(r => r.Headers).Returns(headers);
            mockRequest.Setup(r => r.HttpMethod).Returns("POST");
            mockRequest.Setup(r => r.Url).Returns(new Uri(Url));
            mockRequest.Setup(r => r.ContentType).Returns(ContentType);
            return mockRequest.Object;
        }

        private string CreateHttpDateString() => DateTime.UtcNow.ToString(HmacConstants.DateHeaderFormat, _dateHeaderCulture);
    }
}