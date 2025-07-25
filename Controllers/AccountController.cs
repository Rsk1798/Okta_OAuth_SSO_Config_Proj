using Auth0.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using Okta_OAuth_Config_Proj.Models;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Net.Http;
using System.Net.Http.Headers;
using Newtonsoft.Json;
using Okta_OAuth_Config_Proj.Models;

namespace Okta_OAuth_Config_Proj.Controllers
{
    public class AccountController : Controller
    {

        private readonly IConfiguration _configuration;

        public AccountController(IConfiguration configuration)
        {
            _configuration = configuration;
        }





        public async Task Login(string returnUrl)
        {

            returnUrl = "/Home/Index"; //"https://localhost:44320"

            var authnticationProperties = new LoginAuthenticationPropertiesBuilder()
            // Indicate here where Auth0 should redirect the user after a login.
            // Note that the resulting absolute Uri must be added to the
            // **Allowed Callback URLs** settings for the app.
            .WithRedirectUri(returnUrl).Build();

            await HttpContext.ChallengeAsync(Auth0Constants.AuthenticationScheme, authnticationProperties);

        }



        [Authorize]
        public IActionResult Profile()
        {

            var userProfile = new Okta_OAuth_Config_Proj.Models.UserProfile
            {
                Name = User.Identity.Name,
                Email = User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Email)?.Value,
                ProfileImageUrl = User.Claims.FirstOrDefault(c => c.Type == "picture")?.Value
            };
            return View(userProfile);


            
        }


        //Auth0UserProfileInfo
        [Authorize]
        public async Task<IActionResult> UserProfileInfo()
        {
            // Print all claims to the console for debugging
            //foreach (var claim in User.Claims)
            //{
            //    Console.WriteLine($"CLAIM TYPE: {claim.Type} | VALUE: {claim.Value}");
            //}
            var domain = _configuration["Auth0API:Domain"];
            var clientId = _configuration["Auth0API:ClientId"];
            var clientSecret = _configuration["Auth0API:ClientSecret"];
            var audience = _configuration["Auth0API:Audience"];

            // 1. Get Management API token
            var tokenClient = new HttpClient();
            var tokenRequest = new HttpRequestMessage(HttpMethod.Post, $"https://{domain}/oauth/token");
            tokenRequest.Content = new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>("grant_type", "client_credentials"),
                new KeyValuePair<string, string>("client_id", clientId),
                new KeyValuePair<string, string>("client_secret", clientSecret),
                new KeyValuePair<string, string>("audience", audience)
            });
            var tokenResponse = await tokenClient.SendAsync(tokenRequest);
            var tokenJson = await tokenResponse.Content.ReadAsStringAsync();
            var tokenObj = JsonConvert.DeserializeObject<dynamic>(tokenJson);
            string accessToken = tokenObj.access_token;

            // 2. Get current user's Auth0 user_id from claims
            var userId = User.Claims.FirstOrDefault(c => c.Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier")?.Value;

            // 3. Call Auth0 Management API for user info
            var apiClient = new HttpClient();
            var apiRequest = new HttpRequestMessage(HttpMethod.Get, $"https://{domain}/api/v2/users/{userId}");
            apiRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
            var apiResponse = await apiClient.SendAsync(apiRequest);
            var userInfoJson = await apiResponse.Content.ReadAsStringAsync();
            var userInfo = JsonConvert.DeserializeObject<UserProfile>(userInfoJson);

            return View(userInfo);
        }


        [Authorize]
        public async Task Logout()
        {
            var authenticationProperties = new LogoutAuthenticationPropertiesBuilder()
            // Indicate here where Auth0 should redirect the user after a logout.
            // Note that the resulting absolute Uri must be added to the
            // **Allowed Logout URLs** settings for the app.
            .WithRedirectUri(Url.Action("Index", "Home"))
            .Build();

            await HttpContext.SignOutAsync(Auth0Constants.AuthenticationScheme, authenticationProperties);
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        }

        public IActionResult Index()
        {
            return View();
        }

        //private readonly IConfiguration _configuration;

        //public AccountController(IConfiguration configuration)
        //{
        //    _configuration = configuration;
        //}

        [Authorize]
        public async Task<IActionResult> Auth0UserInfo()
        {
            // Print all claims to the console for debugging
            //foreach (var claim in User.Claims)
            //{
            //    Console.WriteLine($"CLAIM TYPE: {claim.Type} | VALUE: {claim.Value}");
            //}
            var domain = _configuration["Auth0API:Domain"];
            var clientId = _configuration["Auth0API:ClientId"];
            var clientSecret = _configuration["Auth0API:ClientSecret"];
            var audience = _configuration["Auth0API:Audience"];

            // 1. Get Management API token
            var tokenClient = new HttpClient();
            var tokenRequest = new HttpRequestMessage(HttpMethod.Post, $"https://{domain}/oauth/token");
            tokenRequest.Content = new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>("grant_type", "client_credentials"),
                new KeyValuePair<string, string>("client_id", clientId),
                new KeyValuePair<string, string>("client_secret", clientSecret),
                new KeyValuePair<string, string>("audience", audience)
            });
            var tokenResponse = await tokenClient.SendAsync(tokenRequest);
            var tokenJson = await tokenResponse.Content.ReadAsStringAsync();
            var tokenObj = JsonConvert.DeserializeObject<dynamic>(tokenJson);
            string accessToken = tokenObj.access_token;

            // 2. Get current user's Auth0 user_id from claims
            var userId = User.Claims.FirstOrDefault(c => c.Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier")?.Value;

            // 3. Call Auth0 Management API for user info
            var apiClient = new HttpClient();
            var apiRequest = new HttpRequestMessage(HttpMethod.Get, $"https://{domain}/api/v2/users/{userId}");
            apiRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
            var apiResponse = await apiClient.SendAsync(apiRequest);
            var userInfoJson = await apiResponse.Content.ReadAsStringAsync();
            var userInfo = JsonConvert.DeserializeObject<UserProfile>(userInfoJson);

            return View(userInfo);
        }

        [Authorize]
        public async Task<IActionResult> MyPrivacy()
        {
            var domain = _configuration["Auth0API:Domain"];
            var clientId = _configuration["Auth0API:ClientId"];
            var clientSecret = _configuration["Auth0API:ClientSecret"];
            var audience = _configuration["Auth0API:Audience"];

            // 1. Get Management API token
            var tokenClient = new HttpClient();
            var tokenRequest = new HttpRequestMessage(HttpMethod.Post, $"https://{domain}/oauth/token");
            tokenRequest.Content = new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>("grant_type", "client_credentials"),
                new KeyValuePair<string, string>("client_id", clientId),
                new KeyValuePair<string, string>("client_secret", clientSecret),
                new KeyValuePair<string, string>("audience", audience)
            });
            var tokenResponse = await tokenClient.SendAsync(tokenRequest);
            var tokenJson = await tokenResponse.Content.ReadAsStringAsync();
            var tokenObj = JsonConvert.DeserializeObject<dynamic>(tokenJson);
            string accessToken = tokenObj.access_token;

            // 2. Get current user's Auth0 user_id from claims
            var userId = User.Claims.FirstOrDefault(c => c.Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier")?.Value;

            // 3. Call Auth0 Management API for user info
            var apiClient = new HttpClient();
            var apiRequest = new HttpRequestMessage(HttpMethod.Get, $"https://{domain}/api/v2/users/{userId}");
            apiRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
            var apiResponse = await apiClient.SendAsync(apiRequest);
            var userInfoJson = await apiResponse.Content.ReadAsStringAsync();
            var userInfo = JsonConvert.DeserializeObject<UserProfile>(userInfoJson);

            bool consentGiven = userInfo.app_metadata != null && userInfo.app_metadata.privacy_policies == true;
            ViewBag.ConsentGiven = consentGiven;
            return View("~/Views/Home/Privacy.cshtml");
        }
    }
}
