using System;
using System.Collections.Generic;
using System.Configuration;
using System.Globalization;
using System.Linq;
using System.Web;
using Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;
using Microsoft.Owin.Security.Notifications;
using System.Threading.Tasks;
using System.IdentityModel.Claims;

namespace TestWorkbench
{
    public partial class Startup
    {
        private static string clientId = ConfigurationManager.AppSettings["ida:ClientId"];
        private static string aadInstance = EnsureTrailingSlash(ConfigurationManager.AppSettings["ida:AADInstance"]);
        private static string tenantId = ConfigurationManager.AppSettings["ida:TenantId"];
        private static string postLogoutRedirectUri = ConfigurationManager.AppSettings["ida:PostLogoutRedirectUri"];
        private static string authority = aadInstance + tenantId;
        private static string redirectUri = ConfigurationManager.AppSettings["ida:RedirectUri"];

        public void ConfigureAuth(IAppBuilder app)
        {
            app.SetDefaultSignInAsAuthenticationType(CookieAuthenticationDefaults.AuthenticationType);

            app.UseCookieAuthentication(new CookieAuthenticationOptions());

            var options = new OpenIdConnectAuthenticationOptions
            {
                ClientId = clientId,
                Authority = authority,
                PostLogoutRedirectUri = postLogoutRedirectUri,
                Notifications = new OpenIdConnectAuthenticationNotifications()
                {
                    AuthorizationCodeReceived = OnAuthorizationCodeReceived,
                }
            };
            if (!string.IsNullOrEmpty(redirectUri))
            {
                options.RedirectUri = redirectUri;
            }
            app.UseOpenIdConnectAuthentication(options);
        }

        private async Task OnAuthorizationCodeReceived(AuthorizationCodeReceivedNotification context)
        {
            string userObjectID =
                context.AuthenticationTicket.Identity.FindFirst("http://schemas.microsoft.com/identity/claims/objectidentifier").Value;
            try
            {
                var authority = context.Options.Authority;
                string signedUserID = context.AuthenticationTicket.Identity.FindFirst(ClaimTypes.NameIdentifier).Value;
                var currentUri = string.Format("{0}://{1}{2}{3}", context.Request.Scheme, context.Request.Host, context.Request.PathBase, context.Request.Path);
                var result = await GetAccessTokenByCodeAsync(currentUri, authority, signedUserID, context.Code, context.Options.Resource);
                context.AuthenticationTicket.Properties.RedirectUri = currentUri;
            }
            catch (Exception ex)
            { }


        }

        private static string appKey = ConfigurationManager.AppSettings["ida:AppKey"];
        public async static Task GetAccessTokenByCodeAsync(string currentUri, string authority, string signedUserID, string code, string resource)
        {
            ClientCredential credential = new ClientCredential(clientId, appKey);

        }

        private static string EnsureTrailingSlash(string value)
        {
            if (value == null)
            {
                value = string.Empty;
            }

            if (!value.EndsWith("/", StringComparison.Ordinal))
            {
                return value + "/";
            }

            return value;
        }
    }
}
