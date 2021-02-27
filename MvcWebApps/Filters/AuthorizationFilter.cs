using System.Web.Mvc;
using System.Web.Routing;

namespace MvcWebApps.Filters
{
    public class AuthorizationFilter : AuthorizeAttribute, IAuthorizationFilter
    {
        public override void OnAuthorization(AuthorizationContext filterContext)
        {
            //Skip authorization from controller or action where <[AllowAnonymous]> attributes was applied
            bool skipAuthorization = filterContext.ActionDescriptor.IsDefined(typeof(AllowAnonymousAttribute), true)
                                     || filterContext.ActionDescriptor.ControllerDescriptor.IsDefined(typeof(AllowAnonymousAttribute), true);

            string redirectUri = string.IsNullOrEmpty(filterContext.HttpContext.Request.RawUrl) ? "/" : filterContext.HttpContext.Request.RawUrl;

            if (!skipAuthorization)
            {
                if (!filterContext.HttpContext.Request.IsAuthenticated)
                {
                    filterContext.Result = new RedirectToRouteResult(new RouteValueDictionary(new { controller = "Account", action = "SignIn", redirectUri = redirectUri }));
                }
            }
        }
    }
}