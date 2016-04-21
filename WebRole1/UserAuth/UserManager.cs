using Microsoft.AspNet.Identity;
using Microsoft.Owin.Security;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Web;

namespace WebRole1.UserAuth
{
    public static class UserManager
    {
        public const string UserSessionIdClaimType = @"https://connectnow.com.au/claims/usersessionid";

        public static string UserName => UserIdentityClaims.FirstOrDefault(c => c.Type == ClaimTypes.Name).Value;
        public static List<string> UserRoles => UserIdentityClaims.Where(c => c.Type == ClaimTypes.Role).Select(c => c.Value).ToList();
        private static IAuthenticationManager AuthenticationManager => HttpContext.Current.Request.GetOwinContext().Authentication;

        private static IEnumerable<Claim> UserIdentityClaims => ((ClaimsIdentity)HttpContext.Current.User.Identity).Claims;

        public static bool IsAuthorisedUserSessionValid()
        {
            if (HttpContext.Current.Request.IsAuthenticated)
            {
                var sessionIdClaim = UserIdentityClaims.FirstOrDefault(c => c.Type == UserSessionIdClaimType).Value;
                return sessionIdClaim == HttpContext.Current.Session.SessionID;
            }
            return false;
        }

        public static bool SignIn(string userId)
        {
            HttpContext.Current.Session["LoggedinUserId"] = "";
            var claims = GetClaims(userId);
            if (claims != null)
            {
                var claimsIdentity = new ClaimsIdentity(claims, DefaultAuthenticationTypes.ApplicationCookie);

                //This uses OWIN authentication

                AuthenticationManager.SignOut(DefaultAuthenticationTypes.ExternalCookie);
                AuthenticationManager.SignIn(new AuthenticationProperties()
                {
                    //AllowRefresh = true,
                    IsPersistent = false
                }, claimsIdentity);

                HttpContext.Current.User = new ClaimsPrincipal(AuthenticationManager.AuthenticationResponseGrant.Principal);
                HttpContext.Current.Session["LoggedinUserId"] = claims.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier).Value;

                return true;
            }
            return false;
        }

        public static void SignOut()
        {
            AuthenticationManager.SignOut();
        }

        private static List<Claim> GetClaims(string userId)
        {
            var claims = new List<Claim>();
            claims.Add(new Claim(ClaimTypes.Email, "tmukherj2@agl.com.au"));
            claims.Add(new Claim(ClaimTypes.Name, "Tamal Mukherjee"));
            claims.Add(new Claim(ClaimTypes.NameIdentifier, "A105254"));

            var roles = new[] { "Admin", "Citizin", "Worker" };
            var groups = new[] { "Admin", "Citizin", "Worker" };

            foreach (var item in roles)
            {
                claims.Add(new Claim(ClaimTypes.Role, item));
            }
            foreach (var item in groups)
            {
                claims.Add(new Claim(ClaimTypes.GroupSid, item));
            }

            claims.Add(new Claim(UserSessionIdClaimType, HttpContext.Current.Session.SessionID));
            return claims;
        }
    }
}