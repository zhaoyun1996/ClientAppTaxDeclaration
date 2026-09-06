using MISA.ASP.ClientApp.Utils.Logging;
using System;
using System.IO;

namespace MISA.ASP.ClientApp.Utils.FileHandler
{
    public static class FileUtil
    {
        public static string BASE_PATH = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, AppDomain.CurrentDomain.RelativeSearchPath ?? "");

        public static byte[] ConvertStreamToByteArray(this Stream instream)
        {
            try
            {
                if (instream is MemoryStream)
                    return ((MemoryStream)instream).ToArray();

                using (var memoryStream = new MemoryStream())
                {
                    instream.CopyTo(memoryStream);
                    return memoryStream.ToArray();
                }
            }
            catch (Exception ex)
            {
                LogUtil.LogError(ex);
            }

            return null;
        }
    }
}
