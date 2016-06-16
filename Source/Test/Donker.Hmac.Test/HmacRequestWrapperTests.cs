using System;
using System.Collections.Specialized;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Web;
using Donker.Hmac.Helpers;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;

namespace Donker.Hmac.Test
{
    [TestClass]
    public class HmacRequestWrapperTests
    {
        private const string Body = "Example content";
        private byte[] _bodyBytes;
        private Stream _bodyStream;
        private byte[] _md5Hash;
        private HttpContent _httpContent;
        private Stream _httpContentStream;

        [TestInitialize]
        public void Initialize()
        {
            _bodyBytes = Encoding.UTF8.GetBytes(Body);
            _bodyStream = new MemoryStream(_bodyBytes);
            _md5Hash = MD5.Create().ComputeHash(_bodyBytes);
            _httpContent = new ByteArrayContent(_bodyBytes);
            _httpContentStream = _httpContent.ReadAsStreamAsync().Result;
        }

        [TestCleanup]
        public void Cleanup()
        {
            _bodyStream.Dispose();
            _httpContentStream.Dispose();
        }

        [TestMethod]
        public void ShouldWrapHttpRequestMessage()
        {
            // Arrange
            HttpMethod method = HttpMethod.Post;
            Uri uri = new Uri("http://www.example.website/resource.json");
            string contentMd5 = Convert.ToBase64String(_md5Hash);
            const string contentType = "application/json";
            NameValueCollection headers = new NameValueCollection
            {
                {"X-Test-Header", "TestValue"},
                {"Date", "Tue, 15 Nov 1994 08:12:31 GMT"}
            };

            HttpRequestMessage request = new HttpRequestMessage(method, uri);
            request.Headers.Date = new DateTimeOffset(1994, 11, 15, 8, 12, 31, TimeSpan.Zero);
            request.Headers.Add(headers.Keys[0], headers[0]);
            request.Content = _httpContent;
            request.Content.Headers.ContentType = new MediaTypeHeaderValue(contentType);
            request.Content.Headers.ContentMD5 = _md5Hash;

            // Act
            HmacRequestWrapper wrapper = new HmacRequestWrapper(request);

            // Assert
            AssertWrapper(wrapper,
                new DateTimeOffset(1994, 11, 15, 8, 12, 31, TimeSpan.Zero),
                _httpContentStream,
                headers,
                method.Method,
                uri,
                contentMd5,
                contentType);
        }

        [TestMethod]
        public void ShouldWrapHttpRequestBase()
        {
            // Arrange
            string contentMd5 = Convert.ToBase64String(_md5Hash);
            const string contentType = "application/json";

            NameValueCollection headers = new NameValueCollection
            {
                {"X-Test-Header", "TestValue"},
                {"Content-MD5", contentMd5},
                {"Date", "Tue, 15 Nov 1994 08:12:31 GMT"}
            };
            const string method = "POST";
            Uri uri = new Uri("http://www.example.website/resource.json");

            Mock<HttpRequestBase> mockRequest = new Mock<HttpRequestBase>();
            mockRequest.Setup(r => r.InputStream).Returns(_bodyStream);
            mockRequest.Setup(r => r.Headers).Returns(headers);
            mockRequest.Setup(r => r.HttpMethod).Returns(method);
            mockRequest.Setup(r => r.Url).Returns(uri);
            mockRequest.Setup(r => r.ContentType).Returns(contentType);

            // Act
            HmacRequestWrapper wrapper = new HmacRequestWrapper(mockRequest.Object);
            
            // Assert
            AssertWrapper(wrapper,
                new DateTimeOffset(1994, 11, 15, 8, 12, 31, TimeSpan.Zero),
                _bodyStream,
                headers,
                method,
                uri,
                contentMd5,
                contentType);
        }

        private void AssertWrapper(HmacRequestWrapper wrapper, DateTimeOffset? date, Stream content, NameValueCollection headers, string method, Uri requestUri, string contentMd5, string contentType)
        {
            Assert.IsNotNull(wrapper.Date);
            Assert.AreEqual(date, wrapper.Date);
            Assert.IsNotNull(wrapper.Content);
            Assert.IsTrue(ReferenceEquals(content, wrapper.Content));
            Assert.IsNotNull(wrapper.Headers);
            Assert.AreEqual(headers.Count, wrapper.Headers.Count);
            Assert.IsTrue(headers.AllKeys.OrderBy(k => k).SequenceEqual(wrapper.Headers.AllKeys.OrderBy(k => k)));
            Assert.IsNotNull(wrapper.Method);
            Assert.AreEqual(method, wrapper.Method);
            Assert.IsNotNull(wrapper.RequestUri);
            Assert.AreEqual(requestUri.ToString(), wrapper.RequestUri.ToString());
            Assert.IsNotNull(wrapper.ContentMd5);
            Assert.AreEqual(contentMd5, wrapper.ContentMd5);
            Assert.IsNotNull(wrapper.ContentType);
            Assert.AreEqual(contentType, wrapper.ContentType);
        }
    }
}