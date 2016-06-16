using System.Configuration;
using System.Xml;

namespace Donker.Hmac.Configuration
{
    /// <summary>
    /// A handler that returns the XML root node of a configuration section.
    /// </summary>
    public class XmlConfigurationSectionHandler : IConfigurationSectionHandler
    {
        /// <summary>
        /// Returns the XML root node of the configuration section.
        /// </summary>
        /// <param name="parent">The parent object.</param>
        /// <param name="configContext">The configuration context object.</param>
        /// <param name="section">The section XML node.</param>
        /// <returns>The XML root node of the configuration section.</returns>
        public object Create(object parent, object configContext, XmlNode section) => section;
    }
}