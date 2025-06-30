using Auth0.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace Okta_OAuth_Config_Proj.Controllers
{
    public class AccountController : Controller
    {

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
        public IActionResult profile()
        {
            return View(new
            {
                Name = User.Identity.Name,
                EmailAddress = User.Claims.FirstOrDefault(c=>c.Type == ClaimTypes.Email).Value,
                ProfileImage = User.Claims.FirstOrDefault(c=>c.Type == "Picture").Value
            });
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
    }
}
