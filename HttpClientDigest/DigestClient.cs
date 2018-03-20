/*
 * 1. Client makes request
 * 2. Client gets back a nonce from the server and a 401 authentication request
 * 3. Client sends back the following response array 
 *     (username, realm, generate_md5_key(nonce, username, realm, URI, password_given_by_user_to_browser))
 * 4. The server takes username and realm (plus it knows the URI the client is requesting) 
 *     and it looks up the password for that username. Then it goes and does its 
 *     own version of generate_md5_key(nonce, username, realm, URI, password_I_have_for_this_user_in_my_db)
 * 5. It compares the output of generate_md5() that it got with the one the 
 *     client sent, if they match the client sent the correct password. 
 *     If they don't match the password sent was wrong.
 */


using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Newtonsoft.Json.Linq;

namespace HttpClientDigest
{
    public class DigestClient
    {
        static HttpClient client = new HttpClient();

        string _user;
        string _password;
        string _requestMethod;
        string _contentType;
        JObject _postData;
        private string _realm;
        private string _nonce;
        private string _qop;
        private string _cnonce;
        private Algorithm _md5;
        private DateTime _cnonceDate;

        private int _nc;

        public DigestClient (string user, string password)
        {
            _user = user;
            _password = password;

        }

        public string Method
        {
            get { return _requestMethod; }
            set { _requestMethod = value; }
        }

        public string ContentType
        {
            get { return _contentType; }
            set { _contentType = value; }
        }

        public JObject PostData
        {
            get { return _postData; }
            set { _postData = value; }
        }


        public async Task<HttpResponseMessage> GetResponseMessage(Uri uri)
        {
            HttpResponseMessage response = null;

            int infiniteLoopCounter = 0;
            int maxNumberAttempts = 2;

            while ((response == null || response.StatusCode != HttpStatusCode.Accepted) && infiniteLoopCounter < maxNumberAttempts)
            {
                try 
                {
                    client.DefaultRequestHeaders.Clear();
                    // client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                    client.DefaultRequestHeaders.MaxForwards = 1; // Or maybe 0?

                    // If there is a cnonce value, valid for an hour(?), it implies that auth headers have been set, so use them
                    if (!string.IsNullOrEmpty(_cnonce) && DateTime.Now.Subtract(_cnonceDate).TotalHours < 1.0)
                    {
                        client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Digest", ComputeDigestHeader(uri));
                    }

                    try
                    {
                        // Let's just assume it's going to be a post
                        if (Method.Equals("post", StringComparison.CurrentCultureIgnoreCase))
                        {
                            HttpRequestMessage req = new HttpRequestMessage(HttpMethod.Post, uri);
                            req.Content = new StringContent(_postData.ToString(), Encoding.UTF8);

                            response = await client.SendAsync(req);
                        }
                        else
                        {
                            response = await client.GetAsync(uri);
                        }

                        // If the response code is positive then either return the response or loop to the redirection uri
                        if (response.IsSuccessStatusCode)
                        {
                            switch (response.StatusCode)
                            {
                                case HttpStatusCode.OK:
                                case HttpStatusCode.Accepted:
                                    {
                                        return response;
                                    }

                                case HttpStatusCode.Redirect:
                                case HttpStatusCode.Moved:
                                    {
                                        // Read the redirection location from the response headers
                                        List<string> locs = response.Content.Headers.GetValues("Location").ToList<string>();
                                        uri = new Uri(locs.First(l => string.IsNullOrEmpty(l)));

                                        // We decrement the loop counter, as there might be a variable number of redirections which we should follow
                                        infiniteLoopCounter--;

                                        break;
                                    }
                            }
                        }
                        // If the response is negative, this may mean either
                        // 1. There was an error
                        // 2. There was an expected 401 Unauthorised with associated Digest authentication tokens.
                        else
                        {
                            switch (response.StatusCode)
                            {
                                case HttpStatusCode.Unauthorized:
                                    {
                                        // Retrieve the values we need to build up the Digest request headers
                                        // from the 401 unauthorised response headers
                                        var wwwAuthenticateHeader = response.Headers.GetValues("WWW-Authenticate").ToList<string>().First();

                                        _realm = GetDigestHeaderAttribute("realm", wwwAuthenticateHeader);
                                        _nonce = GetDigestHeaderAttribute("nonce", wwwAuthenticateHeader);
                                        _qop = GetDigestHeaderAttribute("qop", wwwAuthenticateHeader);
                                        _md5 = GetMD5Algorithm(wwwAuthenticateHeader);

                                        // Generate a new nonce
                                        _nc = 0;
                                        _cnonce = new Random().Next(123400, 9999999).ToString();
                                        _cnonceDate = DateTime.Now;



                                        client.DefaultRequestHeaders.Clear();
                                        // client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                                        client.DefaultRequestHeaders.MaxForwards = 1; // Or maybe 0?
                                        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Digest", ComputeDigestHeader(uri));

                                        infiniteLoopCounter++;

                                        // Let's just assume it's going to be a post
                                        if (Method.Equals("post", StringComparison.CurrentCultureIgnoreCase))
                                        {
                                            HttpRequestMessage req = new HttpRequestMessage(HttpMethod.Post, uri);
                                            req.Content = new StringContent(_postData.ToString(), Encoding.UTF8);

                                            response = await client.SendAsync(req);
                                        }
                                        else
                                        {
                                            response = await client.GetAsync(uri);
                                        }

                                        break;
                                    }
                                default:
                                    throw new Exception("Error ${response.StatusCode} ${response.StatusCode.ToString()} loading ${uri}");
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        throw ex;
                    }
                }
                catch (Exception ex)
                {
                    throw ex;
                }
            }

            return response;
        }


        /// <summary>
        /// Computes the digest header that should be attached to a request.
        /// </summary>
        /// <returns>The digest header.</returns>
        /// <param name="uri">URI.</param>
        private string ComputeDigestHeader(Uri uri)
        {

            _nc = _nc + 1;

            string ha1, ha2;

            switch (_md5)
            {
                // IIS-Specific
                case Algorithm.MD5sess:
                    {
                        var secret = ComputeMd5Hash(string.Format(CultureInfo.InvariantCulture, "{0}:{1}:{2}", _user, _realm, _password));

                        ha1 = ComputeMd5Hash(string.Format(CultureInfo.InvariantCulture, "{0}:{1}:{2}", secret, _nonce, _cnonce));
                        ha2 = ComputeMd5Hash(string.Format(CultureInfo.InvariantCulture, "{0}:{1}", this.Method.ToUpper(), uri.PathAndQuery));

                        var data = string.Format(CultureInfo.InvariantCulture, "{0}:{1:00000000}:{2}:{3}:{4}",
                            _nonce,
                            _nc,
                            _cnonce,
                            _qop,
                            ha2);

                        var kd = ComputeMd5Hash(string.Format(CultureInfo.InvariantCulture, "{0}:{1}", ha1, data));

                        return string.Format("username=\"{0}\", realm=\"{1}\", nonce=\"{2}\", uri=\"{3}\", " +
                            "algorithm=MD5-sess, response=\"{4}\", qop={5}, nc={6:00000000}, cnonce=\"{7}\"",
                            _user, _realm, _nonce, uri.PathAndQuery, kd, _qop, _nc, _cnonce);
                    }
                // Standard (Apache etc)
                case Algorithm.MD5:
                    {
                        ha1 = ComputeMd5Hash(string.Format("{0}:{1}:{2}", _user, _realm, _password));
                        ha2 = ComputeMd5Hash(string.Format("{0}:{1}", this.Method.ToUpper(), uri.PathAndQuery));

                        var digestResponse = ComputeMd5Hash(string.Format("{0}:{1}:{2:00000000}:{3}:{4}:{5}", ha1, _nonce, _nc, _cnonce, _qop, ha2));

                        return string.Format("username=\"{0}\", realm=\"{1}\", nonce=\"{2}\", uri=\"{3}\", " +
                            "algorithm=MD5, response=\"{4}\", qop={5}, nc={6:00000000}, cnonce=\"{7}\"",
                            _user, _realm, _nonce, uri.PathAndQuery, digestResponse, _qop, _nc, _cnonce);
                    }
            }

            throw new Exception("The digest header could not be generated");
        }


        /// <summary>
        /// Computes the md5 hash of a string.
        /// </summary>
        /// <returns>The md5 hash.</returns>
        /// <param name="input">Input.</param>
        private string ComputeMd5Hash(string input)
        {
            var inputBytes = Encoding.ASCII.GetBytes(input);

            var hash = MD5.Create().ComputeHash(inputBytes);
            var sb = new StringBuilder();

            foreach (var b in hash)
            {
                sb.Append(b.ToString("x2"));
            }
            return sb.ToString();

        }


        /// <summary>
        /// Gets the MD 5 algorithm. This is either straight MD5 or MD5-sess
        /// TODO: find out what the diffference is.
        /// </summary>
        /// <returns>The MD 5 algorithm.</returns>
        /// <param name="digestAuthHeader">Digest auth header.</param>
        private Algorithm GetMD5Algorithm(string digestAuthHeader)
        {
            var md5Regex = new Regex(@"algorithm=(?<algo>.*)[,]", RegexOptions.IgnoreCase);
            var md5Attribute = md5Regex.Match(digestAuthHeader);

            if (md5Attribute.Success)
            {

                char[] charSeparator = new char[] { ',' };

                string algorithm = md5Attribute.Result("${algo}").ToLower().Split(charSeparator)[0];

                switch (algorithm)
                {
                    case "md5-sess":
                    case "\"md5-sess\"":
                        return Algorithm.MD5sess;

                    case "md5":
                    case "\"md5\"":
                    default:
                        return Algorithm.MD5;

                }
            }
            throw new Exception("Could not determine Digest algorithm to be used from the server response.");
        }


        /// <summary>
        /// Gets the digest header attribute from the authentication header which 
        ///  appears to be in attribute="value" format
        /// </summary>
        /// <returns>The digest header attribute.</returns>
        /// <param name="attributeName">Attribute name.</param>
        /// <param name="digestAuthHeader">Digest auth header.</param>
        private string GetDigestHeaderAttribute(string attributeName, string digestAuthHeader)
        {
            var regHeader = new Regex(string.Format(@"{0}=""([^""]*)""", attributeName));
            var matchHeader = regHeader.Match(digestAuthHeader);

            if (matchHeader.Success)
            {
                return matchHeader.Groups[1].Value;
            }
            throw new Exception("Header ${attributeName} not found");

        }


        public enum Algorithm
        {
            MD5 = 0, // Apache Default
            MD5sess = 1 //IIS Default
        }

    }
}
