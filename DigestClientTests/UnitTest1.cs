using System;
using Xunit;
using HttpClientDigest;
using Newtonsoft.Json.Linq;
using Newtonsoft.Json;
using System.Net.Http;
using System.IO;

namespace DigestClientTests
{
    public class UnitTest1
    {
        [Fact]
        public async void Test1()
        {
            var postData = new { cardPaymentRef = "DTC0000001" };

            DigestClient client = new DigestClient("username", "password")
            {
                Method = "POST",
                ContentType = "application/json",
                PostData = JObject.FromObject(postData)
            };

            var response = await client.GetResponseMessage(new Uri(@"https://restapi.somedomain.com/dosomething"));
            var str = await response.Content.ReadAsStringAsync();

            Console.WriteLine(str);
        }


    }
}
