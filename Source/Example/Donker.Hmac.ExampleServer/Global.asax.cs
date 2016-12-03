using System.Web;
using System.Web.Mvc;
using System.Web.Routing;
using Donker.Hmac.Configuration;
using Donker.Hmac.ExampleServer.Attributes;

namespace Donker.Hmac.ExampleServer
{
    public class MvcApplication : HttpApplication
    {
        private IConfigurationManager<HmacConfiguration, string> _hmacConfigurationManager;

        protected void Application_Start()
        {
            _hmacConfigurationManager = new HmacConfigurationManager();
            _hmacConfigurationManager.ConfigureFromFileAndWatch(Server.MapPath("~/Hmac.config"));

            GlobalFilters.Filters.Add(new HmacAuthorizeAttribute(_hmacConfigurationManager));

            AreaRegistration.RegisterAllAreas();
            RouteConfig.RegisterRoutes(RouteTable.Routes);
        }
    }
}
