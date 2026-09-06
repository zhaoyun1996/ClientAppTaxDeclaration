using System.Configuration;

namespace MISA.ASP.ClientApp.Models.Enums
{
    public static class CommonConst
    {
        public readonly static string ASP_API_URL = ConfigurationManager.AppSettings["ASP_Api_Url"] ?? "https://aspapp.misa.vn/Api/";
    }
}
