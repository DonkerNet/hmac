using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Web;
using Donker.Hmac.Configuration;
using Donker.Hmac.Signing;
using Donker.Hmac.Validation;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;

namespace Donker.Hmac.Test
{
    [TestClass]
    public class HmacValidatorTests
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
        public void Intialize()
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
        public void ShouldSucceedValidation()
        {
            // Arrange
            IHmacConfiguration configuration = CreateConfiguration();
            IHmacSigner signer = new HmacSigner(configuration, _keyRepository);
            HmacValidator validator = new HmacValidator(configuration, signer);
            DateTimeOffset dateTimeOffset = DateTimeOffset.UtcNow.AddMinutes(-3);
            string dateString = dateTimeOffset.ToString(HmacConstants.DateHeaderFormat, _dateHeaderCulture);
            HttpRequestBase request = CreateRequest(dateString);
            HmacSignatureData signatureData = signer.GetSignatureDataFromHttpRequest(request);
            string signature = signer.CreateSignature(signatureData);

            request.Headers[HmacConstants.AuthorizationHeaderName] = string.Format(
                HmacConstants.AuthorizationHeaderFormat,
                configuration.AuthorizationScheme,
                signature);

            // Act
            HmacValidationResult result = validator.ValidateHttpRequest(request);

            // Assert
            Assert.IsNotNull(result);
            Assert.IsNull(result.ErrorMessage);
            Assert.AreEqual(result.ResultCode, HmacValidationResultCode.Ok);
        }

        [TestMethod]
        public void ShouldFailValidationDueToMissingDate()
        {
            // Arrange
            IHmacConfiguration configuration = CreateConfiguration();
            IHmacSigner signer = new HmacSigner(configuration, _keyRepository);
            HmacValidator validator = new HmacValidator(configuration, signer);
            DateTimeOffset dateTimeOffset = DateTimeOffset.UtcNow.AddMinutes(-3);
            string dateString = dateTimeOffset.ToString(HmacConstants.DateHeaderFormat, _dateHeaderCulture);
            HttpRequestBase request = CreateRequest(dateString);
            HmacSignatureData signatureData = signer.GetSignatureDataFromHttpRequest(request);
            string signature = signer.CreateSignature(signatureData);

            request.Headers[HmacConstants.AuthorizationHeaderName] = string.Format(
                HmacConstants.AuthorizationHeaderFormat,
                configuration.AuthorizationScheme,
                signature);

            request.Headers.Remove(HmacConstants.DateHeaderName);

            // Act
            HmacValidationResult result = validator.ValidateHttpRequest(request);

            // Assert
            Assert.IsNotNull(result);
            Assert.IsNotNull(result.ErrorMessage);
            Assert.AreEqual(result.ResultCode, HmacValidationResultCode.DateMissing);
        }

        [TestMethod]
        public void ShouldFailValidationDueToInvalidDate()
        {
            // Arrange
            IHmacConfiguration configuration = CreateConfiguration();
            IHmacSigner signer = new HmacSigner(configuration, _keyRepository);
            HmacValidator validator = new HmacValidator(configuration, signer);
            DateTimeOffset dateTimeOffset = DateTimeOffset.UtcNow.AddMinutes(-300);
            string dateString = dateTimeOffset.ToString(HmacConstants.DateHeaderFormat, _dateHeaderCulture);
            HttpRequestBase request = CreateRequest(dateString);
            HmacSignatureData signatureData = signer.GetSignatureDataFromHttpRequest(request);
            string signature = signer.CreateSignature(signatureData);

            request.Headers[HmacConstants.AuthorizationHeaderName] = string.Format(
                HmacConstants.AuthorizationHeaderFormat,
                configuration.AuthorizationScheme,
                signature);

            // Act
            HmacValidationResult result = validator.ValidateHttpRequest(request);

            // Assert
            Assert.IsNotNull(result);
            Assert.IsNotNull(result.ErrorMessage);
            Assert.AreEqual(result.ResultCode, HmacValidationResultCode.DateInvalid);
        }

        [TestMethod]
        public void ShouldFailValidationDueToMissingUsername()
        {
            // Arrange
            IHmacConfiguration configuration = CreateConfiguration();
            IHmacSigner signer = new HmacSigner(configuration, _keyRepository);
            HmacValidator validator = new HmacValidator(configuration, signer);
            DateTimeOffset dateTimeOffset = DateTimeOffset.UtcNow.AddMinutes(-3);
            string dateString = dateTimeOffset.ToString(HmacConstants.DateHeaderFormat, _dateHeaderCulture);
            HttpRequestBase request = CreateRequest(dateString);
            HmacSignatureData signatureData = signer.GetSignatureDataFromHttpRequest(request);
            string signature = signer.CreateSignature(signatureData);

            request.Headers[HmacConstants.AuthorizationHeaderName] = string.Format(
                HmacConstants.AuthorizationHeaderFormat,
                configuration.AuthorizationScheme,
                signature);

            request.Headers["X-Auth-User"] = string.Empty;

            // Act
            HmacValidationResult result = validator.ValidateHttpRequest(request);

            // Assert
            Assert.IsNotNull(result);
            Assert.IsNotNull(result.ErrorMessage);
            Assert.AreEqual(result.ResultCode, HmacValidationResultCode.UsernameMissing);
        }

        [TestMethod]
        public void ShouldFailValidationDueToMissingKey()
        {
            // Arrange
            Mock<IHmacKeyRepository> mockKeyRepo = new Mock<IHmacKeyRepository>();
            mockKeyRepo.Setup(r => r.GetHmacKeyForUsername(It.IsAny<string>())).Returns((string)null);
            IHmacConfiguration configuration = CreateConfiguration();
            IHmacSigner signer = new HmacSigner(configuration, mockKeyRepo.Object);
            HmacValidator validator = new HmacValidator(configuration, signer);
            DateTimeOffset dateTimeOffset = DateTimeOffset.UtcNow.AddMinutes(-3);
            string dateString = dateTimeOffset.ToString(HmacConstants.DateHeaderFormat, _dateHeaderCulture);
            HttpRequestBase request = CreateRequest(dateString);
            HmacSignatureData signatureData = signer.GetSignatureDataFromHttpRequest(request);
            signatureData.Key = "TestKey";
            string signature = signer.CreateSignature(signatureData);

            request.Headers[HmacConstants.AuthorizationHeaderName] = string.Format(
                HmacConstants.AuthorizationHeaderFormat,
                configuration.AuthorizationScheme,
                signature);

            // Act
            HmacValidationResult result = validator.ValidateHttpRequest(request);

            // Assert
            Assert.IsNotNull(result);
            Assert.IsNotNull(result.ErrorMessage);
            Assert.AreEqual(result.ResultCode, HmacValidationResultCode.KeyMissing);
        }

        [TestMethod]
        public void ShouldFailValidationDueToBodyHashMismatch()
        {
            // Arrange
            IHmacConfiguration configuration = CreateConfiguration();
            IHmacSigner signer = new HmacSigner(configuration, _keyRepository);
            HmacValidator validator = new HmacValidator(configuration, signer);
            DateTimeOffset dateTimeOffset = DateTimeOffset.UtcNow.AddMinutes(-3);
            string dateString = dateTimeOffset.ToString(HmacConstants.DateHeaderFormat, _dateHeaderCulture);
            HttpRequestBase request = CreateRequest(dateString);
            HmacSignatureData signatureData = signer.GetSignatureDataFromHttpRequest(request);
            string signature = signer.CreateSignature(signatureData);

            request.Headers[HmacConstants.AuthorizationHeaderName] = string.Format(
                HmacConstants.AuthorizationHeaderFormat,
                configuration.AuthorizationScheme,
                signature);

            request.Headers[HmacConstants.ContentMd5HeaderName] = "blahblah";

            // Act
            HmacValidationResult result = validator.ValidateHttpRequest(request);

            // Assert
            Assert.IsNotNull(result);
            Assert.IsNotNull(result.ErrorMessage);
            Assert.AreEqual(result.ResultCode, HmacValidationResultCode.BodyHashMismatch);
        }

        [TestMethod]
        public void ShouldFailValidationDueToMissingAuthorization()
        {
            // Arrange
            IHmacConfiguration configuration = CreateConfiguration();
            IHmacSigner signer = new HmacSigner(configuration, _keyRepository);
            HmacValidator validator = new HmacValidator(configuration, signer);
            DateTimeOffset dateTimeOffset = DateTimeOffset.UtcNow.AddMinutes(-3);
            string dateString = dateTimeOffset.ToString(HmacConstants.DateHeaderFormat, _dateHeaderCulture);
            HttpRequestBase request = CreateRequest(dateString);
            HmacSignatureData signatureData = signer.GetSignatureDataFromHttpRequest(request);
            string signature = signer.CreateSignature(signatureData);

            request.Headers[HmacConstants.AuthorizationHeaderName] = string.Format(
                HmacConstants.AuthorizationHeaderFormat,
                configuration.AuthorizationScheme,
                signature);

            request.Headers.Remove(HmacConstants.AuthorizationHeaderName);

            // Act
            HmacValidationResult result = validator.ValidateHttpRequest(request);

            // Assert
            Assert.IsNotNull(result);
            Assert.IsNotNull(result.ErrorMessage);
            Assert.AreEqual(result.ResultCode, HmacValidationResultCode.AuthorizationMissing);
        }

        [TestMethod]
        public void ShouldFailValidationDueToInvalidAuthorization()
        {
            // Arrange
            IHmacConfiguration configuration = CreateConfiguration();
            IHmacSigner signer = new HmacSigner(configuration, _keyRepository);
            HmacValidator validator = new HmacValidator(configuration, signer);
            DateTimeOffset dateTimeOffset = DateTimeOffset.UtcNow.AddMinutes(-3);
            string dateString = dateTimeOffset.ToString(HmacConstants.DateHeaderFormat, _dateHeaderCulture);
            HttpRequestBase request = CreateRequest(dateString);

            request.Headers[HmacConstants.AuthorizationHeaderName] = "blahblah";

            // Act
            HmacValidationResult result = validator.ValidateHttpRequest(request);

            // Assert
            Assert.IsNotNull(result);
            Assert.IsNotNull(result.ErrorMessage);
            Assert.AreEqual(result.ResultCode, HmacValidationResultCode.AuthorizationInvalid);
        }

        [TestMethod]
        public void ShouldFailValidationDueToSignatureMismatch()
        {
            // Arrange
            IHmacConfiguration configuration = CreateConfiguration();
            IHmacSigner signer = new HmacSigner(configuration, _keyRepository);
            HmacValidator validator = new HmacValidator(configuration, signer);
            DateTimeOffset dateTimeOffset = DateTimeOffset.UtcNow.AddMinutes(-3);
            string dateString = dateTimeOffset.ToString(HmacConstants.DateHeaderFormat, _dateHeaderCulture);
            HttpRequestBase request = CreateRequest(dateString);

            request.Headers[HmacConstants.AuthorizationHeaderName] = string.Format(
                HmacConstants.AuthorizationHeaderFormat,
                configuration.AuthorizationScheme,
                "blahblah");

            // Act
            HmacValidationResult result = validator.ValidateHttpRequest(request);

            // Assert
            Assert.IsNotNull(result);
            Assert.IsNotNull(result.ErrorMessage);
            Assert.AreEqual(result.ResultCode, HmacValidationResultCode.SignatureMismatch);
        }

        [TestMethod]
        public void ShouldValidateRequestDate()
        {
            // Arrange
            IHmacConfiguration configuration = CreateConfiguration();
            IHmacSigner signer = new HmacSigner(configuration, _keyRepository);
            HmacValidator validator = new HmacValidator(configuration, signer);
            DateTimeOffset dateTimeOffset = DateTimeOffset.UtcNow.AddMinutes(-3);
            string dateString = dateTimeOffset.ToString(HmacConstants.DateHeaderFormat, _dateHeaderCulture);
            DateTime dateTime = dateTimeOffset.UtcDateTime;
            
            // Act
            bool isValidDateTimeOffset = validator.IsValidRequestDate(dateTimeOffset);
            bool isValidDateString = validator.IsValidRequestDate(dateString, HmacConstants.DateHeaderFormat);
            bool isValidDateTime = validator.IsValidRequestDate(dateTime);
            
            // Assert
            Assert.IsTrue(isValidDateString);
            Assert.IsTrue(isValidDateTime);
            Assert.IsTrue(isValidDateTimeOffset);
        }

        [TestMethod]
        public void ShouldFailToValidateRequestDate()
        {
            // Arrange
            IHmacConfiguration configuration = CreateConfiguration();
            IHmacSigner signer = new HmacSigner(configuration, _keyRepository);
            HmacValidator validator = new HmacValidator(configuration, signer);
            DateTimeOffset dateTimeOffset = DateTimeOffset.UtcNow.AddMinutes(-6);
            string dateString = dateTimeOffset.ToString(HmacConstants.DateHeaderFormat, _dateHeaderCulture);
            DateTime dateTime = dateTimeOffset.UtcDateTime;

            // Act
            bool isValidDateTimeOffset = validator.IsValidRequestDate(dateTimeOffset);
            bool isValidDateString = validator.IsValidRequestDate(dateString, HmacConstants.DateHeaderFormat);
            bool isValidDateTime = validator.IsValidRequestDate(dateTime);

            // Assert
            Assert.IsFalse(isValidDateString);
            Assert.IsFalse(isValidDateTime);
            Assert.IsFalse(isValidDateTimeOffset);
        }

        [TestMethod]
        public void ShouldValidateContentMd5()
        {
            // Arrange
            IHmacConfiguration configuration = CreateConfiguration();
            IHmacSigner signer = new HmacSigner(configuration, _keyRepository);
            HmacValidator validator = new HmacValidator(configuration, signer);

            // Act
            bool stringIsValidBase64 = validator.IsValidContentMd5(_base64Md5Hash, Body);
            bool stringIsValidByteArray = validator.IsValidContentMd5(_md5Hash, Body);
            bool bytesAreValidBase64 = validator.IsValidContentMd5(_base64Md5Hash, _bodyBytes);
            bool bytesAreValidByteArray = validator.IsValidContentMd5(_md5Hash, _bodyBytes);
            bool streamIsValidBase64 = validator.IsValidContentMd5(_base64Md5Hash, _bodyStream);
            bool streamIsValidByteArray = validator.IsValidContentMd5(_md5Hash, _bodyStream);

            // Assert
            Assert.IsTrue(stringIsValidBase64);
            Assert.IsTrue(stringIsValidByteArray);
            Assert.IsTrue(bytesAreValidBase64);
            Assert.IsTrue(bytesAreValidByteArray);
            Assert.IsTrue(streamIsValidBase64);
            Assert.IsTrue(streamIsValidByteArray);
        }

        [TestMethod]
        public void ShouldFailToValidateContentMd5()
        {
            // Arrange
            IHmacConfiguration configuration = CreateConfiguration();
            IHmacSigner signer = new HmacSigner(configuration, _keyRepository);
            HmacValidator validator = new HmacValidator(configuration, signer);

            const string incorrectBody = Body + "Modified";
            byte[] incorrectBodyBytes = Encoding.UTF8.GetBytes(incorrectBody);
            Stream incorrectBodyStream = new MemoryStream(incorrectBodyBytes);

            // Act
            bool stringIsValidBase64 = validator.IsValidContentMd5(_base64Md5Hash, incorrectBody);
            bool stringIsValidByteArray = validator.IsValidContentMd5(_md5Hash, incorrectBody);
            bool bytesAreValidBase64 = validator.IsValidContentMd5(_base64Md5Hash, incorrectBodyBytes);
            bool bytesAreValidByteArray = validator.IsValidContentMd5(_md5Hash, incorrectBodyBytes);
            bool streamIsValidBase64 = validator.IsValidContentMd5(_base64Md5Hash, incorrectBodyStream);
            bool streamIsValidByteArray = validator.IsValidContentMd5(_md5Hash, incorrectBodyStream);
            incorrectBodyStream.Dispose();

            // Assert
            Assert.IsFalse(stringIsValidBase64);
            Assert.IsFalse(stringIsValidByteArray);
            Assert.IsFalse(bytesAreValidBase64);
            Assert.IsFalse(bytesAreValidByteArray);
            Assert.IsFalse(streamIsValidBase64);
            Assert.IsFalse(streamIsValidByteArray);
        }

        [TestMethod]
        public void ShouldValidateSignature()
        {
            // Arrange
            IHmacConfiguration configuration = CreateConfiguration();
            IHmacSigner signer = new HmacSigner(configuration, _keyRepository);
            HmacValidator validator = new HmacValidator(configuration, signer);
            const string signatureString1 = "SIGNATURE_STRING";
            const string signatureString2 = "SIGNATURE_STRING";
            byte[] signatureBytes1 = Encoding.UTF8.GetBytes(signatureString1);
            byte[] signatureBytes2 = Encoding.UTF8.GetBytes(signatureString2);

            // Act
            bool isValidString = validator.IsValidSignature(signatureString1, signatureString2);
            bool isValidByteArray = validator.IsValidSignature(signatureBytes1, signatureBytes2);

            // Assert
            Assert.IsTrue(isValidString);
            Assert.IsTrue(isValidByteArray);
        }

        [TestMethod]
        public void ShouldFailToValidateSignature()
        {
            // Arrange
            IHmacConfiguration configuration = CreateConfiguration();
            IHmacSigner signer = new HmacSigner(configuration, _keyRepository);
            HmacValidator validator = new HmacValidator(configuration, signer);
            const string signatureString1 = "SIGNATURE_STRING";
            const string signatureString2 = "SIGNATURE_STRING_DIFFERENT";
            byte[] signatureBytes1 = Encoding.UTF8.GetBytes(signatureString1);
            byte[] signatureBytes2 = Encoding.UTF8.GetBytes(signatureString2);

            // Act
            bool isValidString = validator.IsValidSignature(signatureString1, signatureString2);
            bool isValidByteArray = validator.IsValidSignature(signatureBytes1, signatureBytes2);

            // Assert
            Assert.IsFalse(isValidString);
            Assert.IsFalse(isValidByteArray);
        }

        private IHmacConfiguration CreateConfiguration()
        {
            return new HmacConfiguration
            {
                UserHeaderName = "X-Auth-User",
                AuthorizationScheme = "HMAC",
                SignatureDataSeparator = "\n",
                CharacterEncoding = Encoding.UTF8,
                HmacAlgorithm = "HMACSHA512",
                MaxRequestAge = TimeSpan.FromMinutes(5),
                SignRequestUri = true,
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
    }
}