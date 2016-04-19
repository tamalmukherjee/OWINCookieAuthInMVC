using Microsoft.AspNet.Identity;
using Microsoft.Owin.Security;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Web;
using System.Web.Mvc;

namespace WebRole1.Controllers
{
    public class AccountController : Controller
    {
        //http://www.codeproject.com/Tips/849113/Four-Easy-Steps-to-Set-Up-OWIN-for-Form-authentica

        [AllowAnonymous]
        public ActionResult Login(string returnUrl)
        {
            ViewBag.ReturnUrl = returnUrl;
            if (User.Identity.IsAuthenticated)
                ViewBag.Message = "You Dont have enough Permissions, you need to be with elevated privileges to go there";
            return View();
        }

        //
        // POST: /Account/Login
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public ActionResult Login(string userid, string password, string returnUrl)
        {
            if (userid.Equals(password)) //login check logic
            {
                List<Claim> claims = GetClaims();
                if (null != claims)
                {
                    SignIn(claims);

                    if (!string.IsNullOrEmpty(returnUrl))
                    {
                        return Redirect(returnUrl);
                    }
                    else
                    {
                        return RedirectToAction("Index", "Home");
                    }
                }
            }
            return View();
        }

        private List<Claim> GetClaims()
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
            return claims;
        }

        private void SignIn(List<Claim> claims)
        {
            var claimsIdentity = new ClaimsIdentity(claims, DefaultAuthenticationTypes.ApplicationCookie);

            //This uses OWIN authentication

            AuthenticationManager.SignOut(DefaultAuthenticationTypes.ExternalCookie);
            AuthenticationManager.SignIn(new AuthenticationProperties()
            {
                //AllowRefresh = true,
                IsPersistent = false
            }, claimsIdentity);

            HttpContext.User = new ClaimsPrincipal(AuthenticationManager.AuthenticationResponseGrant.Principal);
            //Session["LoggedinUserId"] = claims.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier).Value;
        }

        private IAuthenticationManager AuthenticationManager
        {
            get
            {
                return HttpContext.GetOwinContext().Authentication;
            }
        }

        private ActionResult RedirectToLocal(string returnUrl)
        {
            if (Url.IsLocalUrl(returnUrl))
            {
                return Redirect(returnUrl);
            }
            else
            {
                return RedirectToAction("Index", "Home");
            }
        }

        
        public ActionResult LogOff()
        {
            AuthenticationManager.SignOut();
            Session.Clear();
            return RedirectToAction("Index", "Home", new { area = "" });
        }
    }
}