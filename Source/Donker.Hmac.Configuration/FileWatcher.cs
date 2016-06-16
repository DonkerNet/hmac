using System;
using System.ComponentModel;
using System.IO;
using System.Threading;

namespace Donker.Hmac.Configuration
{
    internal class FileWatcher : IDisposable
    {
        private readonly object _syncRoot;
        private readonly object _onChangeKey;
        private FileSystemWatcher _fileSystemWatcher;
        private Timer _changeTimer;
        private EventHandlerList _onChangeHandlers;

        private FileSystemEventArgs _recentFileSystemEventArgs;
        private bool _isDisposed;

        public event EventHandler<FileWatcherEventArgs> OnChange
        {
            add
            {
                ThrowExceptionWhenDisposed();
                _onChangeHandlers.AddHandler(_onChangeKey, value);
            }
            remove
            {
                ThrowExceptionWhenDisposed();
                _onChangeHandlers.RemoveHandler(_onChangeKey, value);
            }
        }

        public FileWatcher(FileInfo fileInfo)
        {
            if (fileInfo == null)
                throw new ArgumentNullException(nameof(fileInfo), "The file info cannot be null.");

            _fileSystemWatcher = new FileSystemWatcher
            {
                NotifyFilter = NotifyFilters.CreationTime | NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size
            };

            ChangeFileToWatch(fileInfo);

            _fileSystemWatcher.Created += FileSystemWatcherOnChange;
            _fileSystemWatcher.Changed += FileSystemWatcherOnChange;
            _fileSystemWatcher.Renamed += FileSystemWatcherOnChange;
            _fileSystemWatcher.Deleted += FileSystemWatcherOnChange;

            _changeTimer = new Timer(ChangeTimerOnTick, null, -1, -1);
            _onChangeHandlers = new EventHandlerList();
            _onChangeKey = new object();
            _syncRoot = new object();
        }

        public void ChangeFileToWatch(FileInfo fileInfo)
        {
            ThrowExceptionWhenDisposed();

            if (fileInfo == null)
                throw new ArgumentNullException(nameof(fileInfo), "The file info cannot be null.");

            if (_fileSystemWatcher.Filter != fileInfo.Name)
                _fileSystemWatcher.Filter = fileInfo.Name;
            if (_fileSystemWatcher.Path != fileInfo.DirectoryName)
                _fileSystemWatcher.Path = fileInfo.DirectoryName;
        }

        public void Start()
        {
            ThrowExceptionWhenDisposed();
            _fileSystemWatcher.EnableRaisingEvents = true;
        }

        public void Stop()
        {
            ThrowExceptionWhenDisposed();
            _fileSystemWatcher.EnableRaisingEvents = false;
        }

        private void FileSystemWatcherOnChange(object sender, FileSystemEventArgs args)
        {
            lock (_syncRoot)
            {
                if (_isDisposed)
                    return;

                // Disable events untill they are re-enabled externally using the Start() method
                _fileSystemWatcher.EnableRaisingEvents = false;

                _recentFileSystemEventArgs = args;
                _changeTimer.Change(1000, -1);
            }
        }

        private void ChangeTimerOnTick(object state)
        {
            lock (_syncRoot)
            {
                if (_isDisposed)
                    return;

                FileWatcherEventArgs fileWatcherEventArgs;

                switch (_recentFileSystemEventArgs.ChangeType)
                {
                    case WatcherChangeTypes.Created:
                        fileWatcherEventArgs = FileWatcherEventArgs.ForCreated();
                        break;
                    case WatcherChangeTypes.Changed:
                        fileWatcherEventArgs = FileWatcherEventArgs.ForChanged();
                        break;
                    case WatcherChangeTypes.Renamed:
                        fileWatcherEventArgs = FileWatcherEventArgs.ForRenamed(_recentFileSystemEventArgs.FullPath);
                        break;
                    case WatcherChangeTypes.Deleted:
                        fileWatcherEventArgs = FileWatcherEventArgs.ForDeleted();
                        break;
                    default:
                        return;
                }

                EventHandler<FileWatcherEventArgs> eventHandler = (EventHandler<FileWatcherEventArgs>)_onChangeHandlers[_onChangeKey];
                eventHandler(this, fileWatcherEventArgs);
            }
        }

        private void ThrowExceptionWhenDisposed()
        {
            if (!_isDisposed)
                return;

            Type thisType = GetType();
            throw new ObjectDisposedException(thisType.Name);
        }

        private void Dispose(bool disposing)
        {
            lock (_syncRoot)
            {
                if (_isDisposed)
                    return;

                _isDisposed = true;

                if (disposing)
                {
                    _fileSystemWatcher.Created -= FileSystemWatcherOnChange;
                    _fileSystemWatcher.Changed -= FileSystemWatcherOnChange;
                    _fileSystemWatcher.Renamed -= FileSystemWatcherOnChange;
                    _fileSystemWatcher.Deleted -= FileSystemWatcherOnChange;
                    _fileSystemWatcher.EnableRaisingEvents = false;
                    _fileSystemWatcher.Dispose();
                    _onChangeHandlers.Dispose();
                    _changeTimer.Dispose();
                }

                _fileSystemWatcher = null;
                _onChangeHandlers = null;
                _changeTimer = null;
            }
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        ~FileWatcher()
        {
            Dispose(false);
        }
    }
}