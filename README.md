# httpclient-digest-net-standard - Http Digest Authentication Client

This is a simple class to make it a bit easier to connect a `System.Net.Http.HttpClient` to a web service with Digest Authentication. You might like to use it something like this:

    /// <summary>
    /// Gets the order detail.
    /// </summary>
    /// <returns>The order detail.</returns>
    /// <param name="uri">URI.</param>
    public static async Task<OrderDetailModel> GetOrderDetail(string _paymentref)
    {
      try
      {
        OrderDetailModel odm = null;

        var postData = new { cardPaymentRef = _paymentref };

        DigestClient client = new DigestClient(_username, _password)
        {
            Method = "POST",
            ContentType = "application/json",
            PostData = JObject.FromObject(postData)
        };

        var response = await client.GetResponseMessage(new Uri(_restorderuri));
        var str = await response.Content.ReadAsStringAsync();

        odm = JsonConvert.DeserializeObject<OrderDetailModel>(str);

        return odm;
      }
      catch (Exception ex)
      {
        throw ex;
      }
    }

This has been compiled against dotnet standard 1.6, rather than 2.0, due to issues found with Newtonsoft.Json when compiled into a Nuget package and installed into a dotnet core 2.0 project (see https://stackoverflow.com/questions/49321760/newtonsoft-json-dependency-in-a-net-standard-2-package-causes-runtime-error-in)
