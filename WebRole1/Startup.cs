﻿using System;
using System.Threading.Tasks;
using Microsoft.Owin;
using Owin;
using System.Security.Claims;
using Microsoft.Owin.Security.Cookies;
using Microsoft.AspNet.Identity;
using System.Web.Helpers;

[assembly: OwinStartup(typeof(WebRole1.Startup))]

namespace WebRole1
{
    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            // For more information on how to configure your application, visit http://go.microsoft.com/fwlink/?LinkID=316888
            System.Web.Helpers.AntiForgeryConfig.UniqueClaimTypeIdentifier = ClaimTypes.Email;
            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationType = DefaultAuthenticationTypes.ApplicationCookie,
                CookieName = ".cnusrauth",
                LoginPath = new PathString("/Account/Login"),
                CookieSecure = CookieSecureOption.Always,
                SlidingExpiration = true,
                ExpireTimeSpan = TimeSpan.FromMinutes(30),
                CookieManager = new SystemWebCookieManager()
            });

            AntiForgeryConfig.UniqueClaimTypeIdentifier = ClaimTypes.NameIdentifier;
        }

    }
}
