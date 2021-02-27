using Microsoft.Identity.Client;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Owin;
using Microsoft.Owin.Host.SystemWeb;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.Notifications;
using Microsoft.Owin.Security.OpenIdConnect;
using MvcWebApps.Utils;
using Owin;
using System;
using System.Net;
using System.Security.Claims;
using System.Threading.Tasks;

[assembly: OwinStartup(typeof(MvcWebApps.Startup))]

namespace MvcWebApps
{
    public partial class Startup
    {
        // The Client ID is used by the application to uniquely identify itself to Microsoft identity platform.
        private static string clientId = Globals.ClientId;

        // RedirectUri is the URL where the user will be redirected to after they sign in. RedirectUri should be registered as a valid redirect url for the application
        private static string redirectUri = Globals.RedirectUri;

        // Tenant is the tenant ID (e.g. contoso.onmicrosoft.com, or 'common' for multi-tenant)
        private static string tenant = Globals.TenantId;

        // Azure AD B2C has an OpenID Connect metadata endpoint, which allows an application to get information about Azure AD B2C at runtime.
        // For example, the metadata document for the B2C_1A_AnsysId_signup_signin user flow in <yourtenant>.onmicrosoft.com 
        //tenant is located at: "https://<yourtenant>.b2clogin.com/tfp/<yourtenant>.onmicrosoft.com/B2C_1A_signup_signin/v2.0/.well-known/openid-configuration"
        private static string aadInstance = Globals.AadInstance;

        // B2C policy identifiers
        public static string DefaultPolicy = Globals.SignInSignUpPolicyId;


        // For more information on configuring authentication, please visit http://go.microsoft.com/fwlink/?LinkId=301864
        public void Configuration(IAppBuilder app)
        {
            // Required for Azure webapps, as by default they force TLS 1.2 and this project attempts 1.0
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
            app.SetDefaultSignInAsAuthenticationType(CookieAuthenticationDefaults.AuthenticationType);

            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                // ASP.NET web host compatible cookie manager
                CookieManager = new SystemWebChunkingCookieManager()
            });

           app.UseOpenIdConnectAuthentication(
                new OpenIdConnectAuthenticationOptions
                {
                    // Generate the metadata address using the tenant and policy information
                    MetadataAddress = String.Format(aadInstance, tenant, DefaultPolicy),

                    // These are standard OpenID Connect parameters, with values pulled from web.config
                    ClientId = clientId,
                    RedirectUri = redirectUri,
                    PostLogoutRedirectUri = redirectUri,

                    // Specify the callbacks for each type of notifications
                    Notifications = new OpenIdConnectAuthenticationNotifications
                    {
                        RedirectToIdentityProvider = OnRedirectToIdentityProvider,
                        AuthorizationCodeReceived = OnAuthorizationCodeReceived,
                        AuthenticationFailed = OnAuthenticationFailed,
                    },

                    // Specify the claim type that specifies the Name property.
                    TokenValidationParameters = new TokenValidationParameters
                    {
                        NameClaimType = "name",
                        ValidateIssuer = true
                    },
                    Scope = "openid",

                    // ASP.NET web host compatible cookie manager
                    CookieManager = new SystemWebCookieManager(),

                }
            );
        }

        //On each call to Azure AD B2C, check if a policy(e.g.the profile edit or password reset policy) has been specified in the OWIN context.
        //If so, use that policy when making the call.Also, don't request a code (since it won't be needed).
        private Task OnRedirectToIdentityProvider(RedirectToIdentityProviderNotification<OpenIdConnectMessage, OpenIdConnectAuthenticationOptions> notification)
        {
            var policy = notification.OwinContext.Get<string>("Policy");

            if (!string.IsNullOrEmpty(policy) && !policy.Equals(DefaultPolicy))
            {
                notification.ProtocolMessage.Scope = OpenIdConnectScope.OpenId;
                notification.ProtocolMessage.ResponseType = OpenIdConnectResponseType.IdToken;
                notification.ProtocolMessage.IssuerAddress = notification.ProtocolMessage.IssuerAddress.ToLower().Replace(DefaultPolicy.ToLower(), policy.ToLower());
            }

            return Task.FromResult(0);
        }

        // Catch any failures received by the authentication middleware and handle appropriately

        private Task OnAuthenticationFailed(AuthenticationFailedNotification<OpenIdConnectMessage, OpenIdConnectAuthenticationOptions> notification)
        {
            notification.HandleResponse();

            string nonceWasNull = "IDX21323";
            string cancellationCode = "AADB2C90091";
            string resetPasswordCode = "AADB2C90118";

            // Handle the error code that Azure AD B2C throws when trying to reset a password from the login page
            // because password reset is not supported by a "sign-up or sign-in policy"
            if (notification.ProtocolMessage.ErrorDescription != null && notification.ProtocolMessage.ErrorDescription.Contains(resetPasswordCode))
            {
                // If the user clicked the reset password link, redirect to the reset password route
                notification.Response.Redirect("Account/ResetPassword");
            }
            else if (notification.Exception.Message == "access_denied")
            {
                notification.Response.Redirect("Account/Unauthorized");
            }
            else if (notification.Exception.Message.Contains(cancellationCode))
            {
                // If the user clicked the cancel link, redirect to the signin route
                notification.Response.Redirect("Account/Index");
            }
            else if (notification.Exception.Message.Contains(nonceWasNull))
            {
                // If the user got error for IDX21323
                notification.Response.Redirect($"Account/Secured");
            }
            else
            {
                notification.Response.Redirect("Account/Error");
            }

            return Task.FromResult(0);
        }

        private async Task OnAuthorizationCodeReceived(AuthorizationCodeReceivedNotification notification)
        {
            try
            {
                IConfidentialClientApplication confidentialClient = MsalAppBuilder.BuildConfidentialClientApplication(new ClaimsPrincipal(notification.AuthenticationTicket.Identity));

                // Upon successful sign in, get & cache a token using MSAL
                AuthenticationResult result = await confidentialClient.AcquireTokenByAuthorizationCode(Globals.Scopes, notification.Code).ExecuteAsync();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error :: {ex.Message}");
            }
        }

    }
}
