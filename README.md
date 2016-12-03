# C# HMAC library

A library written in C# to sign and validate HTTP requests using HMAC.

[Download the source code and .NET 4.5 assemblies.][download_link]

## About

A while ago I worked on an MVC web API that used [HMAC][hmac_link] as a means of authentication. I decided to turn that into a library for possible future usage.

The code was written in Visual Studio 2015 and uses C# version 6.0.

There is documentation available [here][documentation_link]. All the code contains XML documentation and the unit tests will also give you some idea on how to use the libraries. I'd also advise you to just play around with it and look at the source code to get more understanding of the library.

**NOTE:** This is just one of the many implementations of HMAC, since it is not an official standard. It is mostly based on [Amazon's implementation for AWS][aws_hmac_link]. It does not mean this library is compatible with other HMAC implementations. For more information about HMAC, read the RFC [here][hmac_rfc_link].

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
- Knowledge of many other things.

## What assemblies are there?
- **Donker.Hmac** contains everything for signing and validating requests;
- **Donker.Hmac.Configuration** contains code for managing HMAC configurations for signing and validating;
- **Donker.Hmac.RestSharp** is an implementation/extension for signing RestSharp requests;
- **Donker.Hmac.Test** contains unit tests for the **Donker.Hmac** assembly;
- **Donker.Hmac.Configuration.Test** contains unit tests for the **Donker.Hmac.Configuration** assembly;
- **Donker.Hmac.RestSharp.Test** contains unit tests for the **Donker.Hmac.RestSharp** assembly.

[hmac_link]: https://en.wikipedia.org/wiki/Hash-based_message_authentication_code
[replay_attack_link]: https://en.wikipedia.org/wiki/Replay_attack
[download_link]: https://github.com/DonkerNET/hmac/releases
[documentation_link]: https://github.com/DonkerNET/hmac/wiki
[aws_hmac_link]: http://docs.aws.amazon.com/AmazonS3/latest/dev/RESTAuthentication.html
[hmac_rfc_link]: https://tools.ietf.org/html/rfc2104