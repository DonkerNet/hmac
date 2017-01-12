namespace Donker.Hmac.Configuration
{
    /// <summary>
    /// Interface for a HMAC configuration manager class used for loading HMAC configuration objects from a file.
    /// </summary>
    public interface IHmacConfigurationManager : IConfigurationManager<IHmacConfiguration, string>
    {
    }
}