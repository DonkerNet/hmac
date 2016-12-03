using System;
using System.Configuration;
using System.Diagnostics;
using Donker.Hmac.Configuration;
using Donker.Hmac.ExampleClient.Models;
using Donker.Hmac.RestSharp.Authenticators;
using Donker.Hmac.RestSharp.Signing;
using Donker.Hmac.Signing;
using RestSharp;
using RestSharp.Deserializers;

namespace Donker.Hmac.ExampleClient
{
    class Program
    {
        static void Main(string[] args)
        {
            // Retrieve the server URL
            string serverBaseUrl = ConfigurationManager.AppSettings["ServerBaseUrl"];

            // Setup the signer
            IConfigurationManager<HmacConfiguration, string> configurationManager = new HmacConfigurationManager();
            configurationManager.ConfigureFromFile("Hmac.config");
            IHmacConfiguration configuration = configurationManager.Get("Example");
            IHmacKeyRepository keyRepository = new SingleHmacKeyRepository("FollowTheWhiteRabbit");
            IRestSharpHmacSigner signer = new RestSharpHmacSigner(configuration, keyRepository);

            // Setup the RestSharp client
            IRestClient client = new RestClient(serverBaseUrl);
            client.AddHandler("application/json", new JsonDeserializer());
            client.Authenticator = new HmacAuthenticator(configuration, signer);
            client.AddDefaultHeader("X-Custom-Header", "Knock knock...");

            // Execute the GET request
            IRestRequest getRequest = new RestRequest("spoon", Method.GET);
            getRequest.AddHeader(configuration.UserHeaderName, "Neo");
            IRestResponse<ExampleModel> getResponse = client.Execute<ExampleModel>(getRequest);
            Console.WriteLine("There is a '{0}'!", getResponse.Data.Value);

            // Execute the POST request
            IRestRequest postRequest = new RestRequest(Method.POST);
            postRequest.RequestFormat = DataFormat.Json;
            postRequest.AddHeader(configuration.UserHeaderName, "Neo");
            postRequest.AddBody(new ExampleModel { Value = "sunglasses" });
            IRestResponse postResponse = client.Execute(postRequest);
            Console.WriteLine(postResponse.Content);

            // Execute GET request with an incorrect username
            IRestRequest incorrectGetRequest = new RestRequest("The One", Method.GET);
            incorrectGetRequest.AddHeader(configuration.UserHeaderName, "Morpheus");
            IRestResponse incorrectGetResponse = client.Execute(incorrectGetRequest);
            Console.WriteLine(incorrectGetResponse.Content);

#if DEBUG
            if (Debugger.IsAttached)
            {
                Console.WriteLine("Press any key to continue . . .");
                Console.ReadKey(true);
            }
#endif
        }
    }
}
