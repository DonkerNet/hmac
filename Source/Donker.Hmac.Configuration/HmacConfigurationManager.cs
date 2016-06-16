using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml;

namespace Donker.Hmac.Configuration
{
    /// <summary>
    /// A configuration manager class that allows for loading multiple HMAC configurations from an XML file.
    /// </summary>
    public sealed class HmacConfigurationManager : ConfigurationManagerBase<HmacConfiguration, string>
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="HmacConfigurationManager"/> class.
        /// </summary>
        public HmacConfigurationManager()
            : base("donker.hmac", "default", StringComparer.Ordinal)
        {
        }

        /// <summary>
        /// Creates a new configuration instance.
        /// </summary>
        /// <returns>A new configuration instance.</returns>
        protected override HmacConfiguration CreateConfigurationInstance() => new HmacConfiguration();

        /// <summary>
        /// Sets the default values for a configuration object.
        /// </summary>
        /// <param name="configuration">The configuration to set the values for.</param>
        protected override void SetDefaultConfigurationValues(HmacConfiguration configuration)
        {
            configuration.Name = DefaultConfigurationKey;
            configuration.UserHeaderName = "X-Auth-User";
            configuration.AuthorizationScheme = "HMAC";
            configuration.SignatureDataSeparator = "\n";
            configuration.CharacterEncoding = Encoding.UTF8;
            configuration.HmacAlgorithm = "HMACSHA512";
            configuration.MaxRequestAge = TimeSpan.FromMinutes(5);
            configuration.SignRequestUri = true;
            configuration.Headers = null;
        }

        /// <summary>
        /// Reads the configurations from an XML application configuration file.
        /// </summary>
        /// <param name="rootElement">The XML root element of the configuration section.</param>
        /// <returns>A dictionary of configurations.</returns>
        protected override IEnumerable<KeyValuePair<string, HmacConfiguration>> ReadXmlAppConfig(XmlElement rootElement) => ReadXml(rootElement);

        /// <summary>
        /// Reads the configurations from an XML file.
        /// </summary>
        /// <param name="fileStream">The stream to the file to read the configurations from.</param>
        /// <param name="fileInfo">Information about the file that is currently opened for reading.</param>
        /// <returns>A dictionary of configurations.</returns>
        protected override IEnumerable<KeyValuePair<string, HmacConfiguration>> ReadConfigurationFile(Stream fileStream, FileInfo fileInfo)
        {
            // This configuration manager implementation only supports XML

            XmlDocument doc = new XmlDocument();

            try
            {
                doc.Load(fileStream);
            }
            catch (Exception ex)
            {
                OnConfigurationError("Could not load the XML document from the file stream.", ex);
                return null;
            }

            return ReadXml(doc.DocumentElement);
        }

        /// <summary>
        /// Reads the configurations from an XML string.
        /// </summary>
        /// <param name="config">The string to read the configurations from.</param>
        /// <param name="format">Specified in which format the config is written. Currently only 'XML' is allowed.</param>
        /// <returns>A dictionary of configurations.</returns>
        /// <exception cref="ArgumentException">The specified format is not XML.</exception>
        protected override IEnumerable<KeyValuePair<string, HmacConfiguration>> ReadConfigurationString(string config, string format)
        {
            if (!string.Equals(format, HmacConfigurationFormat.Xml, StringComparison.OrdinalIgnoreCase))
                throw new ArgumentException("The configuration manager only supports XML as the format.", nameof(format));

            XmlDocument doc = new XmlDocument();

            try
            {
                using (StringReader reader = new StringReader(config))
                {
                    doc.Load(reader);
                }
            }
            catch (Exception ex)
            {
                OnConfigurationError("Could not load the XML document from the config string.", ex);
                return null;
            }

            return ReadXml(doc.DocumentElement);
        }

        private IEnumerable<KeyValuePair<string, HmacConfiguration>> ReadXml(XmlElement rootElement)
        {
            IDictionary<string, HmacConfiguration> configurations = new Dictionary<string, HmacConfiguration>();

            XmlNode configurationsNode = rootElement.ChildNodes
                .Cast<XmlNode>()
                .FirstOrDefault(n => n.Name == "configurations");

            if (configurationsNode != null)
            {
                foreach (XmlNode addNode in configurationsNode.ChildNodes)
                {
                    if (addNode.Name != "configuration")
                        continue;

                    HmacConfiguration configuration = CreateConfigurationInstance();
                    SetDefaultConfigurationValues(configuration);

                    if (addNode.Attributes != null)
                    {
                        foreach (XmlAttribute attribute in addNode.Attributes)
                        {
                            string value = attribute.Value;
                            if (string.IsNullOrEmpty(value))
                                continue;

                            switch (attribute.Name)
                            {
                                case "name":
                                    configuration.Name = value;
                                    break;
                                case "userHeaderName":
                                    configuration.UserHeaderName = value;
                                    break;
                                case "authorizationScheme":
                                    configuration.AuthorizationScheme = value;
                                    break;
                                case "signatureDataSeparator":
                                    try
                                    {
                                        configuration.SignatureDataSeparator = Regex.Unescape(value);
                                    }
                                    catch (ArgumentException ex)
                                    {
                                        OnConfigurationError("Configuration attribute 'signatureDataSeparator' contains an unrecognized escape sequence.", ex);
                                        return null;
                                    }
                                    break;
                                case "characterEncoding":
                                    try
                                    {
                                        configuration.CharacterEncoding = Encoding.GetEncoding(value);
                                    }
                                    catch (Exception ex)
                                    {
                                        OnConfigurationError("Configuration attribute 'characterEncoding' does not have a valid name.", ex);
                                        return null;
                                    }
                                    break;
                                case "hmacAlgorithm":
                                    configuration.HmacAlgorithm = value;
                                    break;
                                case "maxRequestAge":
                                    try
                                    {
                                        double maxRequestAge = double.Parse(value);
                                        configuration.MaxRequestAge = TimeSpan.FromSeconds(maxRequestAge);
                                    }
                                    catch (Exception ex)
                                    {
                                        OnConfigurationError("Configuration attribute 'maxRequestAge' does not have a valid number value.", ex);
                                        return null;
                                    }
                                    break;
                                case "signRequestUri":
                                    try
                                    {
                                        configuration.SignRequestUri = bool.Parse(value);
                                    }
                                    catch (Exception ex)
                                    {
                                        OnConfigurationError("Configuration attribute 'signRequestUri' does not have a valid boolean value.", ex);
                                        return null;
                                    }
                                    break;
                            }
                        }
                    }

                    if (string.IsNullOrEmpty(configuration.Name))
                    {
                        OnConfigurationError("The configuration must have a name.", null);
                        return null;
                    }

                    foreach (XmlNode headerNode in addNode.ChildNodes)
                    {
                        if (headerNode.Name != "headers")
                            continue;

                        if (headerNode.ChildNodes.Count == 0)
                            continue;

                        configuration.Headers = new List<string>();

                        foreach (XmlNode headerAddNode in headerNode.ChildNodes)
                        {
                            if (headerAddNode.Name != "add")
                                continue;

                            string headerName = null;

                            if (headerAddNode.Attributes != null)
                            {
                                foreach (XmlAttribute headerAddNodeAttribute in headerAddNode.Attributes)
                                {
                                    if (headerAddNodeAttribute.Name == "name")
                                    {
                                        headerName = headerAddNodeAttribute.Value;
                                        break;
                                    }
                                }
                            }

                            if (string.IsNullOrEmpty(headerName))
                            {
                                OnConfigurationError("A valid header name attribute was not found.", null);
                                return null;
                            }

                            configuration.Headers.Add(headerName);
                        }

                        break;
                    }

                    if (configurations.ContainsKey(configuration.Name))
                    {
                        OnConfigurationError("A configuration with the same name already exists.", null);
                        return null;
                    }

                    configurations.Add(configuration.Name, configuration);
                }
            }

            return configurations;
        }

        /// <summary>
        /// Called when an error occured during the processing of the configuration file.
        /// </summary>
        /// <param name="message">The message describing the error.</param>
        /// <param name="exception">The exception that may have occured.</param>
        protected override void OnConfigurationError(string message, Exception exception)
        {
            throw new HmacConfigurationException(message, exception);
        }
    }
}