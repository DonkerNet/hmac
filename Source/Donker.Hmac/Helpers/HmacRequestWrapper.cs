using System;
using System.Collections.Specialized;
using System.Globalization;
using System.IO;
using System.Net.Http;
using System.Web;

namespace Donker.Hmac.Helpers
{
    internal class HmacRequestWrapper
    {
        public DateTimeOffset? Date { get; }
        public Stream Content { get; }
        public NameValueCollection Headers { get; }
        public string Method { get; }
        public Uri RequestUri { get; }
        public string ContentMd5 { get; }
        public string ContentType { get; }

        public HmacRequestWrapper(HttpRequestMessage request)
        {
            if (request == null)
                throw new ArgumentNullException(nameof(request), "The request cannot be null.");

            Headers = new NameValueCollection();

            if (request.Headers != null)
            {
                Date = request.Headers.Date;
                
                foreach (var header in request.Headers)
                {
                    if (header.Value != null)
                    {
                        foreach (string value in header.Value)
                            Headers.Add(header.Key, value);
                    }
                    else
                    {
                        Headers.Add(header.Key, string.Empty);
                    }
                }
            }

            if (request.Content != null)
            {
                Content = request.Content.ReadAsStreamAsync().Result;
                
                if (request.Content.Headers != null)
                {
                    ContentType = request.Content.Headers.ContentType.ToString();
                    ContentMd5 = Convert.ToBase64String(request.Content.Headers.ContentMD5);
                }
            }
            
            Method = request.Method.Method;
            RequestUri = request.RequestUri;
        }

        public HmacRequestWrapper(HttpRequestBase request)
        {
            if (request == null)
                throw new ArgumentNullException(nameof(request), "The request cannot be null.");

            if (request.Headers != null)
            {
                Headers = request.Headers;
                ContentMd5 = Headers[HmacConstants.ContentMd5HeaderName];

                string dateString = Headers[HmacConstants.DateHeaderName];
                if (dateString != null)
                {
                    DateTimeOffset date;
                    bool hasDate = DateTimeOffset.TryParseExact(
                        dateString,
                        HmacConstants.DateHeaderFormat,
                        CultureInfo.GetCultureInfo(HmacConstants.DateHeaderCulture),
                        DateTimeStyles.AssumeUniversal,
                        out date);

                    if (hasDate)
                        Date = date;
                }
            }
            else
            {
                Headers = new NameValueCollection();
            }

            Content = request.InputStream;
            Method = request.HttpMethod;
            RequestUri = request.Url;
            ContentType = request.ContentType;
        }
    }
}