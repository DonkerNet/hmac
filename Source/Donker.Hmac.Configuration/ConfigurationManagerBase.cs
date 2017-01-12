using System;
using System.Collections.Generic;
using System.Configuration;
using System.IO;
using System.Xml;

namespace Donker.Hmac.Configuration
{
    /// <summary>
    /// Base class for a configuration manager class used for loading configuration objects from a file.
    /// </summary>
    /// <typeparam name="TConfiguration">The type of configurations that are managed.</typeparam>
    /// <typeparam name="TKey">The key used to retrieve a configuration.</typeparam>
    public abstract class ConfigurationManagerBase<TConfiguration, TKey> : IConfigurationManager<TConfiguration, TKey>, IDisposable
        where TConfiguration : ICloneableConfiguration // Configurations are cloned to prevent outside changes to the configuration in the dictionary
    {
        private readonly object _syncRoot;
        private readonly string _sectionName;
        private readonly TKey _defaultConfigurationKey;
        private readonly Dictionary<TKey, TConfiguration> _configurations;
        private readonly IEqualityComparer<TKey> _keyComparer;

        private FileWatcher _fileWatcher;
        private bool _isDisposed;

        /// <summary>
        /// Gets the name of the configuration section in the configuration file.
        /// </summary>
        /// <exception cref="ObjectDisposedException">The configuration manager has been disposed of.</exception>
        public string SectionName
        {
            get
            {
                ThrowExceptionWhenDisposed();
                return _sectionName;
            }
        }
        /// <summary>
        /// Gets the key that can be used to retrieve the default configuration.
        /// </summary>
        /// <exception cref="ObjectDisposedException">The configuration manager has been disposed of.</exception>
        public TKey DefaultConfigurationKey
        {
            get
            {
                ThrowExceptionWhenDisposed();
                return _defaultConfigurationKey;
            }
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="ConfigurationManagerBase{TConfiguration,TKey}"/> class.
        /// </summary>
        /// <param name="sectionName">The name of the configuration section in the configuration file.</param>
        /// <param name="defaultConfigurationKey">The key that can be used to retrieve the default configuration.</param>
        /// <param name="keyComparer">The comparer to use when retrieving configurations by key.</param>
        /// <exception cref="ArgumentNullException">The section name or default configuration key is null.</exception>
        /// <exception cref="ArgumentException">The section name is empty.</exception>
        protected ConfigurationManagerBase(string sectionName, TKey defaultConfigurationKey, IEqualityComparer<TKey> keyComparer)
        {
            if (sectionName == null)
                throw new ArgumentNullException(nameof(sectionName), "The section name cannot be null.");
            if (sectionName.Length == 0)
                throw new ArgumentException("The section name cannot be empty.", nameof(sectionName));
            if (Equals(defaultConfigurationKey, null))
                throw new ArgumentNullException(nameof(defaultConfigurationKey), "The default configuration key cannot be null.");

            _syncRoot = new object();
            _sectionName = sectionName;
            _defaultConfigurationKey = defaultConfigurationKey;
            _configurations = keyComparer != null
                ? new Dictionary<TKey, TConfiguration>(keyComparer)
                : new Dictionary<TKey, TConfiguration>();
            _keyComparer = keyComparer;
        }

        /// <summary>
        /// Gets the default configuration.
        /// </summary>
        /// <returns>A new configuration instance.</returns>
        /// <exception cref="ObjectDisposedException">The configuration manager has been disposed of.</exception>
        public TConfiguration GetDefault()
        {
            ThrowExceptionWhenDisposed();

            TConfiguration configuration;

            lock (_syncRoot)
            {
                if (!_configurations.TryGetValue(_defaultConfigurationKey, out configuration))
                    configuration = AddDefaultConfiguration();

                configuration = (TConfiguration)configuration.Clone();
            }

            return configuration;
        }

        /// <summary>
        /// Gets a key collection of all the configurations that are available.
        /// </summary>
        /// <returns>A collection of keys.</returns>
        /// <exception cref="ObjectDisposedException">The configuration manager has been disposed of.</exception>
        public ICollection<TKey> GetAllKeys()
        {
            ThrowExceptionWhenDisposed();

            TKey[] keys;

            lock (_syncRoot)
            {
                int keyCount = _configurations.Count;

                if (keyCount == 0)
                {
                    keys = new[] { DefaultConfigurationKey };
                }
                else if (!_configurations.ContainsKey(DefaultConfigurationKey))
                {
                    keys = new TKey[++keyCount];
                    keys[0] = DefaultConfigurationKey;
                    _configurations.Keys.CopyTo(keys, 1);
                }
                else
                {
                    keys = new TKey[keyCount];
                    _configurations.Keys.CopyTo(keys, 0);
                }
            }

            return keys;
        }

        /// <summary>
        /// Tries to get the configuration for the specified key.
        /// </summary>
        /// <param name="key">The key to retrieve the configuration for.</param>
        /// <param name="configuration">The retrieved configuration instance.</param>
        /// <returns><c>true</c> if found; otherwise, <c>false</c>.</returns>
        /// <exception cref="ArgumentNullException">The key is null.</exception>
        /// <exception cref="ObjectDisposedException">The configuration manager has been disposed of.</exception>
        public bool TryGet(TKey key, out TConfiguration configuration)
        {
            ThrowExceptionWhenDisposed();

            if (Equals(key, null))
                throw new ArgumentNullException(nameof(key), "The key cannot be null.");

            bool isFound = false;

            lock (_syncRoot)
            {
                if (_configurations.TryGetValue(key, out configuration))
                {
                    configuration = (TConfiguration)configuration.Clone();
                    isFound = true;
                }
                else
                {
                    bool isDefault = _keyComparer?.Equals(key, DefaultConfigurationKey) ?? Equals(key, DefaultConfigurationKey);

                    if (isDefault)
                    {
                        configuration = (TConfiguration)AddDefaultConfiguration().Clone();
                        isFound = true;
                    }
                }
            }

            return isFound;
        }

        /// <summary>
        /// Gets the configuration for the specified key.
        /// </summary>
        /// <param name="key">The key to retrieve the configuration for.</param>
        /// <returns>A new configuration instance.</returns>
        /// <exception cref="ArgumentNullException">The key is null.</exception>
        /// <exception cref="ObjectDisposedException">The configuration manager has been disposed of.</exception>
        public TConfiguration Get(TKey key)
        {
            TConfiguration configuration;

            if (!TryGet(key, out configuration))
            {
                OnConfigurationError($"The configuration with key '{key}' was not found.", null);
                return default(TConfiguration);
            }

            return configuration;
        }

        /// <summary>
        /// Checks if a configuration exists for the specified key.
        /// </summary>
        /// <param name="key">The key of the configuration to find.</param>
        /// <returns><c>true</c> if found; otherwise, <c>false</c>.</returns>
        /// <exception cref="ArgumentNullException">The key is null.</exception>
        /// <exception cref="ObjectDisposedException">The configuration manager has been disposed of.</exception>
        public bool Contains(TKey key)
        {
            ThrowExceptionWhenDisposed();

            if (Equals(key, null))
                throw new ArgumentNullException(nameof(key), "The key cannot be null.");

            bool isFound;

            lock (_syncRoot)
            {
                isFound = _configurations.ContainsKey(key);

                if (!isFound)
                    isFound = _keyComparer?.Equals(key, DefaultConfigurationKey) ?? Equals(key, DefaultConfigurationKey);
            }

            return isFound;
        }

        /// <summary>
        /// Loads all configurations from the specified string.
        /// </summary>
        /// <param name="config">The string to load the configurations from.</param>
        /// <param name="format">Specified in which format the config is written (XML, JSON, etc.).</param>
        /// <exception cref="ArgumentNullException">The config string is null.</exception>
        /// <exception cref="ArgumentException">The config string is empty.</exception>
        /// <exception cref="ObjectDisposedException">The configuration manager has been disposed of.</exception>
        public void ConfigureFromString(string config, string format)
        {
            ThrowExceptionWhenDisposed();

            if (config == null)
                throw new ArgumentNullException(nameof(config), "The config string cannot be null.");
            if (config.Length == 0)
                throw new ArgumentException("The config string cannot be empty.", nameof(config));
          
            IEnumerable<KeyValuePair<TKey, TConfiguration>> newConfigurations = ReadConfigurationString(config, format);
            ProcessConfig(newConfigurations);
        }

        /// <summary>
        /// Loads all configurations from an XML application configuration file.
        /// </summary>
        /// <exception cref="ObjectDisposedException">The configuration manager has been disposed of.</exception>
        public void ConfigureFromXmlAppConfig()
        {
            ThrowExceptionWhenDisposed();

            XmlElement rootElement = ConfigurationManager.GetSection(_sectionName) as XmlElement;
            if (rootElement == null)
            {
                OnConfigurationError("No configuration section was found in the application configuration file.", null);
                return;
            }

            IEnumerable<KeyValuePair<TKey, TConfiguration>> newConfigurations = ReadXmlAppConfig(rootElement);
            ProcessConfig(newConfigurations);
        }

        /// <summary>
        /// Loads all configurations from the specified file.
        /// </summary>
        /// <param name="file">The file to load the configurations from.</param>
        /// <exception cref="FileNotFoundException">The configuration file was not found.</exception>
        /// <exception cref="ObjectDisposedException">The configuration manager has been disposed of.</exception>
        public void ConfigureFromFile(FileInfo file)
        {
            ThrowExceptionWhenDisposed();
            ConfigureFromFileInternal(file);
        }

        /// <summary>
        /// Loads all configurations from the specified file.
        /// </summary>
        /// <param name="filePath">The path to the file to load the configurations from.</param>
        /// <exception cref="FileNotFoundException">The configuration file was not found.</exception>
        /// <exception cref="ObjectDisposedException">The configuration manager has been disposed of.</exception>
        public void ConfigureFromFile(string filePath)
        {
            ThrowExceptionWhenDisposed();
            FileInfo file = new FileInfo(filePath);
            ConfigureFromFileInternal(file);
        }

        /// <summary>
        /// Loads all configurations from the specified file and watches this file for any changes.
        /// </summary>
        /// <param name="file">The file to load the configurations from.</param>
        /// <exception cref="FileNotFoundException">The configuration file was not found.</exception>
        /// <exception cref="ObjectDisposedException">The configuration manager has been disposed of.</exception>
        public void ConfigureFromFileAndWatch(FileInfo file)
        {
            ThrowExceptionWhenDisposed();
            ConfigureFromFileAndWatchInternal(file);
        }

        /// <summary>
        /// Loads all configurations from the specified file and watches this file for any changes.
        /// </summary>
        /// <param name="filePath">The path to the file to load the configurations from.</param>
        /// <exception cref="FileNotFoundException">The configuration file was not found.</exception>
        /// <exception cref="ObjectDisposedException">The configuration manager has been disposed of.</exception>
        public void ConfigureFromFileAndWatch(string filePath)
        {
            ThrowExceptionWhenDisposed();
            FileInfo file = new FileInfo(filePath);
            ConfigureFromFileAndWatchInternal(file);
        }

        private void ConfigureFromFileInternal(FileInfo file)
        {
            if (!File.Exists(file.FullName))
                throw new FileNotFoundException("The specified configuration file was not found.", file.FullName);

            IEnumerable<KeyValuePair<TKey, TConfiguration>> newConfigurations;

            using (Stream fileStream = File.OpenRead(file.FullName))
                newConfigurations = ReadConfigurationFile(fileStream, file);

            ProcessConfig(newConfigurations);
        }

        private void ConfigureFromFileAndWatchInternal(FileInfo file)
        {
            if (_fileWatcher != null)
            {
                ConfigureFromFileInternal(file);

                lock (_syncRoot)
                {
                    _fileWatcher.ChangeFileToWatch(file);
                    _fileWatcher.Start();
                }

                return;
            }

            ConfigureFromFileInternal(file);

            EventHandler<FileWatcherEventArgs> onChange = (sender, args) =>
            {
                if (args.IsFileNameChanged)
                {
                    ConfigureFromFileAndWatchInternal(new FileInfo(args.NewFilePath));
                }
                else if (!args.IsFileDeleted)
                {
                    ConfigureFromFileInternal(file);

                    lock (_syncRoot)
                    {
                        _fileWatcher.Start();
                    }
                }
            };

            lock (_syncRoot)
            {
                _fileWatcher = new FileWatcher(file);
                _fileWatcher.OnChange += onChange;
                _fileWatcher.Start();
            }
        }

        private void ProcessConfig(IEnumerable<KeyValuePair<TKey, TConfiguration>> newConfigurations)
        {
            string error = null;

            lock (_syncRoot)
            {
                _configurations.Clear();

                if (newConfigurations != null)
                {
                    bool defaultOverwritten = false;

                    foreach (KeyValuePair<TKey, TConfiguration> kvp in newConfigurations)
                    {
                        if (_defaultConfigurationKey.Equals(kvp.Key))
                        {
                            if (defaultOverwritten)
                            {
                                error = "The default configuration has been specified more than once.";
                                break;
                            }

                            _configurations[kvp.Key] = kvp.Value;
                            defaultOverwritten = true;
                        }
                        else
                        {
                            if (_configurations.ContainsKey(kvp.Key))
                            {
                                error = "A configuration with the same name already exists.";
                                break;
                            }

                            _configurations.Add(kvp.Key, kvp.Value);
                        }
                    }

                    if (!defaultOverwritten)
                    {
                        // A default config was not found, so create one
                        AddDefaultConfiguration();
                    }
                }
            }

            if (error != null)
                OnConfigurationError(error, null);
        }

        private TConfiguration AddDefaultConfiguration()
        {
            TConfiguration defaultConfig = CreateConfigurationInstance();
            SetDefaultConfigurationValues(defaultConfig);
            _configurations.Add(_defaultConfigurationKey, defaultConfig);
            return defaultConfig;
        }

        /// <summary>
        /// Creates a new configuration instance.
        /// </summary>
        /// <returns>A new configuration instance.</returns>
        protected abstract TConfiguration CreateConfigurationInstance();

        /// <summary>
        /// Sets the default values for a configuration object.
        /// </summary>
        /// <param name="configuration">The configuration to set the values for.</param>
        protected abstract void SetDefaultConfigurationValues(TConfiguration configuration);

        /// <summary>
        /// Reads the configurations from application configuration file.
        /// </summary>
        /// <param name="rootElement">The XML root element of the configuration section.</param>
        /// <returns>A dictionary of configurations.</returns>
        protected abstract IEnumerable<KeyValuePair<TKey, TConfiguration>> ReadXmlAppConfig(XmlElement rootElement);

        /// <summary>
        /// Reads the configurations from the file.
        /// </summary>
        /// <param name="fileStream">The stream to the file to read the configurations from.</param>
        /// <param name="fileInfo">Information about the file that is currently opened for reading.</param>
        /// <returns>A dictionary of configurations.</returns>
        protected abstract IEnumerable<KeyValuePair<TKey, TConfiguration>> ReadConfigurationFile(Stream fileStream, FileInfo fileInfo);

        /// <summary>
        /// Reads the configurations from a string.
        /// </summary>
        /// <param name="config">The string to read the configurations from.</param>
        /// <param name="format">Specified in which format the config is written (XML, JSON, etc.).</param>
        /// <returns>A dictionary of configurations.</returns>
        protected abstract IEnumerable<KeyValuePair<TKey, TConfiguration>> ReadConfigurationString(string config, string format);

        /// <summary>
        /// Called when an error occured during the processing of the configuration file.
        /// </summary>
        /// <param name="message">The message describing the error.</param>
        /// <param name="exception">The exception that may have occured.</param>
        protected abstract void OnConfigurationError(string message, Exception exception);

        /// <summary>
        /// Throws an exception if the configuration manager has been disposed.
        /// </summary>
        protected void ThrowExceptionWhenDisposed()
        {
            if (!_isDisposed)
                return;

            Type thisType = GetType();
            throw new ObjectDisposedException(thisType.Name);
        }

        /// <summary>
        /// Disposes of the resources used by this configuration manager.
        /// </summary>
        /// <param name="disposing">Whether to dispose of managed resources or not.</param>
        protected virtual void Dispose(bool disposing)
        {
            if (_isDisposed)
                return;

            _isDisposed = true;

            if (disposing)
            {
                _fileWatcher?.Dispose();
            }

            _fileWatcher = null;
        }

        /// <summary>
        /// Disposes of the resources used by this configuration manager.
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Destroys the configuration manager.
        /// </summary>
        ~ConfigurationManagerBase()
        {
            Dispose(false);
        }
    }
}