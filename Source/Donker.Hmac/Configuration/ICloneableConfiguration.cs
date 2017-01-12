namespace Donker.Hmac.Configuration
{
    // NOTE: this interface was made to avoid any confusion about the meaning/usage of the .NET ICloneable interface

    /// <summary>
    /// Interface for cloning configuration objects so that any modifications do not affect their original instances.
    /// </summary>
    public interface ICloneableConfiguration
    {
        /// <summary>
        /// Creates a copy of the current instance, ensuring that any modifications made to the copy do not affect the instance it was copied from.
        /// </summary>
        /// <returns>The new configuration instance.</returns>
        object Clone();
    }
}