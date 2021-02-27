using Microsoft.Owin.Security;
using Microsoft.Owin.Security.OpenIdConnect;
using MvcWebApps.Utils;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;

namespace MvcWebApps.Controllers
{
    [Authorize]
    public class AccountController : Controller
    {
        // GET: Account
        public ActionResult Index()
        {
            return View();
        }

        // GET: Account/SignIn
        [AllowAnonymous]
        public void SignIn(string redirectUri)
        {
            if (!Request.IsAuthenticated)
            {
                redirectUri = redirectUri ?? "/";

                HttpContext.GetOwinContext().Set("Policy", Globals.SignInSignUpPolicyId);
                var authenticationProperties = new AuthenticationProperties { RedirectUri = redirectUri };
                HttpContext.GetOwinContext().Authentication.Challenge(authenticationProperties, OpenIdConnectAuthenticationDefaults.AuthenticationType);

                return;
            }
        }

        // GET: Account/SignOut
        public async Task SignOut()
        {
            await MsalAppBuilder.ClearUserTokenCache();

            IEnumerable<AuthenticationDescription> authTypes = HttpContext.GetOwinContext().Authentication.GetAuthenticationTypes();
            HttpContext.GetOwinContext().Authentication.SignOut(authTypes.Select(t => t.AuthenticationType).ToArray());
            Request.GetOwinContext().Authentication.GetAuthenticationTypes();
        }

        //GET: Account/ResetPassword
        public void ResetPassword()
        {
            // Let the middleware know you are trying to use the reset password policy (see OnRedirectToIdentityProvider in Startup.cs)
            HttpContext.GetOwinContext().Set("Policy", Globals.ResetPasswordPolicyId);

            // Set the page to redirect to after changing passwords
            var authenticationProperties = new AuthenticationProperties { RedirectUri = "Account/Index" };
            HttpContext.GetOwinContext().Authentication.Challenge(authenticationProperties);
            return;
        }

        //GET: Account/EditProfile
        public void EditProfile()
        {
            // Let the middleware know you are trying to use the profile editing policy (see OnRedirectToIdentityProvider in Startup.cs)
            HttpContext.GetOwinContext().Set("Policy", Globals.ProfileEditingPolicyId);

            // Set the page to redirect to after editing profile
            var authenticationProperties = new AuthenticationProperties { RedirectUri = "Account/Index" };
            HttpContext.GetOwinContext().Authentication.Challenge(authenticationProperties);
            return;
        }

        //GET: Account/Unauthorized
        [AllowAnonymous]
        public ActionResult Unauthorized()
        {
            return View();
        }

        //GET: Account/Error
        [AllowAnonymous]
        public ActionResult Error()
        {
            return View();
        }
    }
}