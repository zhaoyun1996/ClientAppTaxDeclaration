using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MISA.ASP.ClientApp.Models
{
    public class CaptchaResult
    {
        public byte[] ByteArray { get; set; }
        public string Base64Img { get; set; }
        public string Result { get; set; } = string.Empty;
        public string Key { get; set; } = string.Empty;
    }
}
