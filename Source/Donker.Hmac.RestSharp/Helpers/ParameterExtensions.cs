using System;
using System.Collections.Generic;
using System.Linq;
using RestSharp;

namespace Donker.Hmac.RestSharp.Helpers
{
    /// <summary>
    /// Extension methods for RestSharp <see cref="Parameter"/> objects and collections.
    /// </summary>
    public static class ParameterExtensions
    {
        /// <summary>
        /// Searches for the body parameter in two RestSharp parameter collections. If one could not be found in the main source, the additional source will be searched.
        /// </summary>
        /// <param name="mainSource">The main source collection in which to search for the body parameter.</param>
        /// <param name="additionalSource">Additional parameter collection to search through.</param>
        /// <returns>The <see cref="Parameter"/> object if found; otherwise, <c>null</c>.</returns>
        /// <exception cref="ArgumentNullException">The main source is null.</exception>
        public static Parameter GetBodyParameter(this IEnumerable<Parameter> mainSource, IEnumerable<Parameter> additionalSource)
        {
            if (mainSource == null)
                throw new ArgumentNullException(nameof(mainSource), "The main source cannot be null.");

            Func<Parameter, bool> predicate = p => p != null
                && p.Type == ParameterType.RequestBody;

            Parameter result = mainSource.FirstOrDefault(predicate);
            if (result != null)
                return result;

            if (additionalSource != null)
            {
                result = additionalSource.FirstOrDefault(predicate);
                return result;
            }

            return null;
        }

        /// <summary>
        /// Searches for the body parameter in a RestSharp parameter collection.
        /// </summary>
        /// <param name="source">The collection in which to search for the body parameter.</param>
        /// <returns>The <see cref="Parameter"/> object if found; otherwise, <c>null</c>.</returns>
        /// <exception cref="ArgumentNullException">The source is null.</exception>
        public static Parameter GetBodyParameter(this IEnumerable<Parameter> source) => GetBodyParameter(source, null);

        /// <summary>
        /// Searches for a header parameter in two RestSharp parameter collections. If one could not be found in the main source, the additional source will be searched.
        /// </summary>
        /// <param name="mainSource">The main source collection in which to search for the header parameter.</param>
        /// <param name="headerName">The name of the header to find.</param>
        /// <param name="additionalSource">Additional parameter collection to search through.</param>
        /// <returns>The <see cref="Parameter"/> object if found; otherwise, <c>null</c>.</returns>
        /// <exception cref="ArgumentNullException">The main source or header name is null.</exception>
        /// <exception cref="ArgumentException">The header name is empty.</exception>
        public static Parameter GetHeaderParameter(this IEnumerable<Parameter> mainSource, string headerName, IEnumerable<Parameter> additionalSource)
        {
            if (mainSource == null)
                throw new ArgumentNullException(nameof(mainSource), "The main source cannot be null.");
            if (headerName == null)
                throw new ArgumentNullException(nameof(headerName), "The header name cannot be null.");
            if (headerName == null)
                throw new ArgumentException("The header name cannot be empty.", nameof(headerName));

            Func<Parameter, bool> predicate = p => p != null
                && p.Type == ParameterType.HttpHeader
                && string.Equals(p.Name, headerName, StringComparison.OrdinalIgnoreCase);

            Parameter result = mainSource.FirstOrDefault(predicate);
            if (result != null)
                return result;

            if (additionalSource != null)
            {
                result = additionalSource.FirstOrDefault(predicate);
                return result;
            }

            return null;
        }

        /// <summary>
        /// Searches for a header parameter in a RestSharp parameter collection.
        /// </summary>
        /// <param name="source">The collection in which to search for the header parameter.</param>
        /// <param name="headerName">The name of the header to find.</param>
        /// <returns>The <see cref="Parameter"/> object if found; otherwise, <c>null</c>.</returns>
        /// <exception cref="ArgumentNullException">The source or header name is null.</exception>
        /// <exception cref="ArgumentException">The header name is empty.</exception>
        public static Parameter GetHeaderParameter(this IEnumerable<Parameter> source, string headerName) => GetHeaderParameter(source, headerName, null);

        /// <summary>
        /// Tries to get the values of a header from two RestSharp parameter collections. If one could not be found in the main source, the additional source will be searched.
        /// </summary>
        /// <param name="mainSource">The main source collection in which to search for the header.</param>
        /// <param name="headerName">The name of the header to get the values for.</param>
        /// <param name="results">If successful, this will contain all the values of the header that were found.</param>
        /// <param name="additionalSource">Additional parameter collection to search through.</param>
        /// <returns><c>true</c> if one or more values were found; otherwise, <c>false</c>.</returns>
        /// <exception cref="ArgumentNullException">The main source or header name is null.</exception>
        /// <exception cref="ArgumentException">The header name is empty.</exception>
        public static bool TryGetHeaderValues(this IEnumerable<Parameter> mainSource, string headerName, out IEnumerable<string> results, IEnumerable<Parameter> additionalSource)
        {
            if (mainSource == null)
                throw new ArgumentNullException(nameof(mainSource), "The main source cannot be null.");
            if (headerName == null)
                throw new ArgumentNullException(nameof(headerName), "The header name cannot be null.");
            if (headerName == null)
                throw new ArgumentException("The header name cannot be empty.", nameof(headerName));

            Func<Parameter, bool> predicate = p => p != null
                && p.Type == ParameterType.HttpHeader
                && string.Equals(p.Name, headerName, StringComparison.OrdinalIgnoreCase)
                && p.Value != null;

            List<string> resultList = mainSource
                .Where(predicate)
                .Select(p => p.Value.ToString())
                .ToList();

            if (additionalSource != null)
            {
                resultList.AddRange(additionalSource
                    .Where(predicate)
                    .Select(p => p.Value.ToString()));
            }

            results = resultList;
            return resultList.Count > 0;
        }

        /// <summary>
        /// Tries to get the values of a header from a RestSharp parameter collection.
        /// </summary>
        /// <param name="source">The collection in which to search for the header.</param>
        /// <param name="headerName">The name of the header to get the values for.</param>
        /// <param name="results">If successful, this will contain all the values of the header that were found.</param>
        /// <returns><c>true</c> if one or more values were found; otherwise, <c>false</c>.</returns>
        /// <exception cref="ArgumentNullException">The source or header name is null.</exception>
        /// <exception cref="ArgumentException">The header name is empty.</exception>
        public static bool TryGetHeaderValues(this IEnumerable<Parameter> source, string headerName, out IEnumerable<string> results) => TryGetHeaderValues(source, headerName, out results, null);
    }
}