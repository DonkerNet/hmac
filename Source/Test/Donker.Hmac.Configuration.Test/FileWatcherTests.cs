using System.IO;
using System.Threading;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Donker.Hmac.Configuration.Test
{
    [TestClass]
    public class FileWatcherTests
    {
        [TestMethod]
        public void ShouldWatchCreatedFile()
        {
            // Arrange
            FileWatcherEventArgs args = null;
            const string fileName = "FileWatcherCreate.test";
            FileWatcher fileWatcher = new FileWatcher(new FileInfo(fileName));
            fileWatcher.OnChange += (s, a) => args = a;
            
            // Act
            fileWatcher.Start();
            using (StreamWriter writer = File.CreateText(fileName))
            {
                writer.WriteLine();
                writer.Flush();
            }
            Thread.Sleep(1200);
            fileWatcher.Dispose();
            File.Delete(fileName);

            // Assert
            Assert.IsNotNull(args);
            Assert.IsTrue(args.IsFileCreated);
        }

        [TestMethod]
        public void ShouldWatchChangedFile()
        {
            // Arrange
            FileWatcherEventArgs args = null;
            const string fileName = "FileWatcherChange.test";
            FileWatcher fileWatcher = new FileWatcher(new FileInfo(fileName));
            fileWatcher.OnChange += (s, a) => args = a;
            using (StreamWriter writer = File.CreateText(fileName))
            {
                writer.WriteLine();
                writer.Flush();
            }

            // Act
            fileWatcher.Start();
            using (StreamWriter writer = new StreamWriter(fileName, true))
            {
                writer.WriteLine();
                writer.Flush();
            }
            Thread.Sleep(1200);
            fileWatcher.Dispose();
            File.Delete(fileName);

            // Assert
            Assert.IsNotNull(args);
            Assert.IsTrue(args.IsFileChanged);
        }

        [TestMethod]
        public void ShouldWatchRenamedFile()
        {
            // Arrange
            FileWatcherEventArgs args = null;
            const string fileName = "FileWatcherRename.test";
            const string fileName2 = "FileWatcherRename2.test";
            FileWatcher fileWatcher = new FileWatcher(new FileInfo(fileName));
            fileWatcher.OnChange += (s, a) => args = a;
            using (StreamWriter writer = File.CreateText(fileName))
            {
                writer.WriteLine();
                writer.Flush();
            }

            // Act
            fileWatcher.Start();
            File.Move(fileName, fileName2);
            Thread.Sleep(1200);
            FileWatcherEventArgs previousArgs = args;
            fileWatcher.ChangeFileToWatch(new FileInfo(fileName2));
            fileWatcher.Start();
            File.Delete(fileName2);
            Thread.Sleep(1200);
            fileWatcher.Dispose();

            // Assert
            Assert.IsNotNull(previousArgs);
            Assert.IsTrue(previousArgs.IsFileNameChanged);
            Assert.IsNotNull(previousArgs.NewFilePath);
            Assert.AreEqual(fileName2, new FileInfo(previousArgs.NewFilePath).Name);
            Assert.IsNotNull(args);
            Assert.IsTrue(args.IsFileDeleted);
        }

        [TestMethod]
        public void ShouldWatchDeletedFile()
        {
            // Arrange
            FileWatcherEventArgs args = null;
            const string fileName = "FileWatcherDelete.test";
            FileWatcher fileWatcher = new FileWatcher(new FileInfo(fileName));
            fileWatcher.OnChange += (s, a) => args = a;
            using (StreamWriter writer = File.CreateText(fileName))
            {
                writer.WriteLine();
                writer.Flush();
            }

            // Act
            fileWatcher.Start();
            File.Delete(fileName);
            Thread.Sleep(1200);
            fileWatcher.Dispose();

            // Assert
            Assert.IsNotNull(args);
            Assert.IsTrue(args.IsFileDeleted);
        }
    }
}