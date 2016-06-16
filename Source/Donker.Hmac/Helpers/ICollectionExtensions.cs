using System.Collections.Generic;

namespace Donker.Hmac.Helpers
{
    /// <summary>
    /// Extension methods for <see cref="ICollection{T}"/> objects.
    /// </summary>
    public static class ICollectionExtensions
    {
        /// <summary>
        /// Checks whether the collection is null or empty.
        /// </summary>
        /// <typeparam name="T">The type of the items in the collection.</typeparam>
        /// <param name="collection">The collection to check.</param>
        /// <returns><c>true</c> if null or empty; otherwise, <c>false</c>.</returns>
        public static bool IsNullOrEmpty<T>(this ICollection<T> collection)
        {
            return collection == null || collection.Count == 0;
        }
    }
}