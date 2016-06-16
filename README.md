# C# HMAC library

A library written in C# to sign and validate HTTP requests using HMAC.

[Download the source code and .NET 4.5 assemblies.][download_link]

## About

A while ago I worked on an MVC web API that used [HMAC][hmac_link] as a means of authentication. I decided to turn that into a library for possible future usage.

The code was written in Visual Studio 2015 and uses C# version 6.0.

This is a first version and could possibly still contain some bugs.

There is no documentation available (since I'm too lazy to write some), but all the code contains XML documentation and the unit tests will give you some idea on how to use the libraries. You'll also find a few basic examples further on, but I'd advise you to just play around with it and look at the source code to get some understanding of the library.

## What can you do with this library?
- Sign an HTTP request using HMAC;
- Sign a RestSharp request using HMAC;
- Validate a request that was signed using HMAC;
- Easily create a Content-MD5 hash;
- Avoid [replay-attacks][replay_attack_link];
- It's almost fully extensible;
- And there's probably some other stuff I forgot to put here.

## What do you need for this library?
- Knowledge of HTTP;
- Knowledge of HMAC;
- Knowledge of ASP.NET;
- Knowledge of many other things;
- The patience to get to know this library because I'm too lazy to write proper documentation.

## What assemblies are there?
- **Donker.Hmac** contains everything for signing and validating requests;
- **Donker.Hmac.Configuration** contains code for managing HMAC configurations for signing and validating;
- **Donker.Hmac.RestSharp** is an implementation/extension for signing RestSharp requests;
- **Donker.Hmac.Test** contains unit tests for the **Donker.Hmac** assembly;
- **Donker.Hmac.Configuration.Test** contains unit tests for the **Donker.Hmac.Configuration** assembly;
- **Donker.Hmac.RestSharp.Test** contains unit tests for the **Donker.Hmac.RestSharp** assembly.
 
## Example code

### Signing and validation

```C#
// The following request is just an example, could also be an HttpRequestMessage instead
HttpRequestBase exampleRequest = CreateRequest();

// In this example, a username is required for signing so we add it to a custom header
exampleRequest.Headers["X-Auth-User"] = "John Doe";

// We also set some other header that we also want to sign
exampleRequest.Headers["X-Example-Useless-Header"] = "some pointless example value";

// Create a configuration to tell the signer how it should sign requests
IHmacConfiguration configuration = new HmacConfiguration
{
    Name = "My awesome configuration",
    UserHeaderName = "X-Auth-User", // Only when usernames are required
    AuthorizationScheme = "HMAC", // Will be used in the final Authorization header
    SignatureDataSeparator = "\r", // Separate signature data by a new line before signing
    CharacterEncoding = Encoding.UTF8, // The encoding to use
    HmacAlgorithm = "HMACSHA512", // The algorithm to use
    MaxRequestAge = TimeSpan.FromMinutes(15), // Validation fails if requests are older than 15 minutes
    SignRequestUri = true, // Include the request URI into the signature (problematic when using a proxy)
    Headers = new List<string> { "X-Example-Useless-Header" } // Include our custom header for signing
};

// Create a repository that returns a key to use for signing
// You can create your own repositories as long as they implement the IHmacKeyRepository interface
IHmacKeyRepository keyRepository = new SingleUserHmacKeyRepository("John Doe", "example key 123");

// Create the signer
IHmacSigner signer = new HmacSigner(configuration, keyRepository);

// If the request has no MD5 hash yet but there is a body,
// we create the hash here and add it so we can use it for the signature later
if (exampleRequest.InputStream != null
    && string.IsNullOrEmpty(exampleRequest.Headers[HmacConstants.ContentMd5HeaderName]))
{
    string md5Hash = signer.CreateBase64Md5Hash(exampleRequest.InputStream);
    exampleRequest.Headers[HmacConstants.ContentMd5HeaderName] = md5Hash;
}

// Extract the data we want to sign from the request, which depends on the IHmacConfiguration used
// This will also retrieve the key from the IHmacKeyRepository and add it to the resulting data
HmacSignatureData signatureData = signer.GetSignatureDataFromHttpRequest(exampleRequest);

// Now we create the signature
string signature = signer.CreateSignature(signatureData);

// And we add it to the request
signer.AddAuthorizationHeader(exampleRequest, signature);

// Done! Let's validate it! Which is something you'd normally do server side
// We will need to use the same configuration and a signer using the same configuration
// or signatures won't match
IHmacValidator validator = new HmacValidator(configuration, signer);

// Validate
HmacValidationResult validationResult = validator.ValidateHttpRequest(exampleRequest);

// Check the result code
if (validationResult.ResultCode != HmacValidationResultCode.Ok)
    throw new Exception(
        $"Validation failed. Reason: {validationResult.ErrorMessage}");
```

### Signing RestSharp requests

```C#
// Create a configuration to tell the signer how it should sign requests
IHmacConfiguration configuration = new HmacConfiguration
{
    Name = "My awesome configuration",
    UserHeaderName = "X-Auth-User", // Only when usernames are required
    AuthorizationScheme = "HMAC", // Will be used in the final Authorization header
    SignatureDataSeparator = "\r", // Separate signature data by a new line before signing
    CharacterEncoding = Encoding.UTF8, // The encoding to use
    HmacAlgorithm = "HMACSHA512", // The algorithm to use
    MaxRequestAge = TimeSpan.FromMinutes(15), // Validation fails if requests are older than 15 minutes
    SignRequestUri = true, // Include the request URI into the signature (problematic when using a proxy)
    Headers = new List<string> { "X-Example-Useless-Header" } // Include our custom header for signing
};

// Create a repository that returns a key to use for signing
// You can create your own repositories as long as they implement the IHmacKeyRepository interface
IHmacKeyRepository keyRepository = new SingleUserHmacKeyRepository("John Doe", "example key 123");

// Create the signer
IRestSharpHmacSigner signer = new RestSharpHmacSigner(configuration, keyRepository);

// Setup the client and add the authenticator
IRestClient client = new RestClient("http://example.url");
client.Authenticator = new HmacAuthenticator(configuration, signer);

// Create a request
IRestRequest request = new RestRequest("SomeResource", Method.POST);
request.AddBody("Example body"); // The authenticator will create an MD5 hash
request.AddHeader("X-Auth-User", "John Doe"); // We require a user in this example

// And then execute the request, resulting in RestSharp automatically signing it with the authenticator
client.Execute(request);
```

### Managing configurations

```C#
// Create a new manager instance
HmacConfigurationManager configurationManager = new HmacConfigurationManager();

// Configure from a separate file and watch for changes
configurationManager.ConfigureFromFileAndWatch("Hmac.config");

// Get configs
HmacConfiguration defaultConfig = configurationManager.GetDefault();
HmacConfiguration customConfig = configurationManager.Get("MyCustomConfiguration");
```

#### Example XML configuration

App.config
```XML
<?xml version="1.0" encoding="utf-8" ?>
<configuration>
  <configSections>
    <section name="donker.hmac" type="Donker.Hmac.Configuration.XmlConfigurationSectionHandler, Donker.Hmac.Configuration" />
  </configSections>
  <donker.hmac configSource="Hmac.config" />
</configuration>
```

Separate config file
```XML
<?xml version="1.0" encoding="utf-8"?>
<donker.hmac>
  <configurations>
    <configuration name="TestConfiguration"
         userHeaderName="X-Test-User"
         authorizationScheme="TEST"
         signatureDataSeparator="_"
         characterEncoding="UTF-32"
         hmacAlgorithm="HMACSHA256"
         maxRequestAge="120"
         signRequestUri="false">
      <headers>
        <add name="X-Test-Header-1" />
        <add name="X-Test-Header-2" />
      </headers>
    </configuration>
  </configurations>
</donker.hmac>
```

[hmac_link]: https://en.wikipedia.org/wiki/Hash-based_message_authentication_code
[replay_attack_link]: https://en.wikipedia.org/wiki/Replay_attack
[download_link]: https://github.com/DonkerNET/hmac/releases
