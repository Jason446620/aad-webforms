using System;
using System.Collections.Generic;
using System.Configuration;
using System.Globalization;
using System.Threading.Tasks;
using System.Linq;
using System.Web;
using Microsoft.Owin.Extensions;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;
using Owin;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.Owin.Security.Notifications;
using Microsoft.IdentityModel.Logging;

namespace WebApplication1
{
    public partial class Startup
    {
        //private static string clientId = ConfigurationManager.AppSettings["ida:ClientID"];
        //private static string aadInstance = EnsureTrailingSlash(ConfigurationManager.AppSettings["ida:AADInstance"]);
        //private static string authority = aadInstance + "common";
        // The Client ID is used by the application to uniquely identify itself to Microsoft identity platform.
        string clientId = System.Configuration.ConfigurationManager.AppSettings["ida:ClientId"];

        // RedirectUri is the URL where the user will be redirected to after they sign in.
        string redirectUri = System.Configuration.ConfigurationManager.AppSettings["ida:RedirectUri"];

        // Tenant is the tenant ID (e.g. contoso.onmicrosoft.com, or 'common' for multi-tenant)
        static string tenant = System.Configuration.ConfigurationManager.AppSettings["ida:Tenant"];

        // Authority is the URL for authority, composed of the Microsoft identity platform and the tenant name (e.g. https://login.microsoftonline.com/contoso.onmicrosoft.com/v2.0)
        string authority = String.Format(System.Globalization.CultureInfo.InvariantCulture, System.Configuration.ConfigurationManager.AppSettings["ida:Authority"], tenant);

        public void ConfigureAuth(IAppBuilder app)
        {
            IdentityModelEventSource.ShowPII = true;

            app.SetDefaultSignInAsAuthenticationType(CookieAuthenticationDefaults.AuthenticationType);

            app.UseCookieAuthentication(new CookieAuthenticationOptions { });

            // instead of using the default validation (validating against a single issuer value, as we do in line of business apps), 
            // we inject our own multitenant validation logic
            app.UseOpenIdConnectAuthentication(
                new OpenIdConnectAuthenticationOptions
                {
                    // Sets the ClientId, authority, RedirectUri as obtained from web.config
                    ClientId = clientId,
                    Authority = authority,
                    RedirectUri = redirectUri,
                    // PostLogoutRedirectUri is the page that users will be redirected to after sign-out. In this case, it is using the home page
                    PostLogoutRedirectUri = redirectUri,
                    Scope = OpenIdConnectScope.OpenIdProfile,
                    // ResponseType is set to request the code id_token - which contains basic information about the signed-in user
                    ResponseType = OpenIdConnectResponseType.CodeIdToken,

                    TokenValidationParameters = new Microsoft.IdentityModel.Tokens.TokenValidationParameters
                    {
                        NameClaimType = "preferred_username",
                        ValidateIssuer = true // Simplification (see note below)
                    },
                    Notifications = new OpenIdConnectAuthenticationNotifications()
                    {   
                        SecurityTokenValidated = (context) =>
                        {
                            // If your authentication logic is based on users
                            return Task.FromResult(0);
                        },
                        AuthenticationFailed = (context) =>
                        {
                            // Pass in the context back to the app
                            context.HandleResponse();
                            // Suppress the exception
                            return Task.FromResult(0);
                        }
                    }
                });

            // This makes any middleware defined above this line run before the Authorization rule is applied in web.config
            app.UseStageMarker(PipelineStage.Authenticate);
        }
        /// <summary>
        /// Handle failed authentication requests by redirecting the user to the home page with an error in the query string
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        private Task OnAuthenticationFailed(AuthenticationFailedNotification<OpenIdConnectMessage, OpenIdConnectAuthenticationOptions> context)
        {
            context.HandleResponse();
            context.Response.Redirect("/?errormessage=" + context.Exception.Message);
            return Task.FromResult(0);
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
