using System.IO;

namespace MISA.ASP.ClientApp.Models
{
    public class CaptchaRequest
    {
        public Stream Stream { get; set; }

        public string Base64Image { get; set; }

        public string Source { get; set; }
    }
}
