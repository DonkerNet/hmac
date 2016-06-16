using System;

namespace Donker.Hmac.Configuration
{
    internal class FileWatcherEventArgs : EventArgs
    {
        public bool IsFileCreated { get; private set; }
        public bool IsFileChanged { get; private set; }
        public bool IsFileDeleted { get; private set; }
        public bool IsFileNameChanged { get; private set; }
        public string NewFilePath { get; private set; }

        private FileWatcherEventArgs()
        {
        }

        public static FileWatcherEventArgs ForCreated() => new FileWatcherEventArgs { IsFileCreated = true };

        public static FileWatcherEventArgs ForChanged() => new FileWatcherEventArgs { IsFileChanged = true };

        public static FileWatcherEventArgs ForDeleted() => new FileWatcherEventArgs { IsFileDeleted = true };

        public static FileWatcherEventArgs ForRenamed(string newFilePath)
        {
            if (newFilePath == null)
                throw new ArgumentNullException(nameof(newFilePath), "The new file path cannot be null.");
            if (newFilePath.Length == 0)
                throw new ArgumentException("The new file path cannot be empty.", nameof(newFilePath));

            return new FileWatcherEventArgs
            {
                IsFileNameChanged = true,
                NewFilePath = newFilePath
            };
        }
    }
}