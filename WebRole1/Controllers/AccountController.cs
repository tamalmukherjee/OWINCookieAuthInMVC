using System.Collections.Generic;
using System.Security.Claims;
using System.Web.Mvc;

namespace WebRole1.Controllers
{
    public class AccountController : BaseController
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
                if (UserAuth.UserManager.SignIn(userid))
                {
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
            UserAuth.UserManager.SignOut();
            Session.Clear();
            return RedirectToAction("Index", "Home", new { area = "" });
        }
    }
}