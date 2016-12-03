using System.IO;
using System.Runtime.Serialization.Json;
using System.Web.Helpers;
using System.Web.Mvc;
using System.Web.Script.Serialization;
using Donker.Hmac.ExampleServer.Models;

namespace Donker.Hmac.ExampleServer.Controllers
{
    [Route("example")]
    public class ExampleController : Controller
    {
        [HttpGet]
        [Route("{value}")]
        public ActionResult Get(string value)
        {
            if (string.IsNullOrEmpty(value))
                return HttpNotFound();
            return Json(new ExampleModel { Value = value }, JsonRequestBehavior.AllowGet);
        }

        [HttpPost]
        [Route("")]
        public ActionResult Post()
        {
            string json;

            Request.InputStream.Seek(0, SeekOrigin.Begin);

            using (StreamReader reader = new StreamReader(Request.InputStream))
                json = reader.ReadToEnd();

            JavaScriptSerializer jsSerializer = new JavaScriptSerializer();
            ExampleModel model = jsSerializer.Deserialize<ExampleModel>(json);

            if (string.IsNullOrEmpty(model?.Value))
                return HttpNotFound();
            return Content($"Succesfully posted your '{model.Value}'.");
        }
    }
}