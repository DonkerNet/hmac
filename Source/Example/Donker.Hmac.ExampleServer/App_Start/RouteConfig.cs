using System.Web.Mvc;
using System.Web.Routing;

namespace Donker.Hmac.ExampleServer
{
    public class RouteConfig
    {
        public static void RegisterRoutes(RouteCollection routes)
        {
            routes.MapMvcAttributeRoutes();
        }
    }
}
