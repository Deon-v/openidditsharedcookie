using System;
using System.IO;
using System.Net.Http.Headers;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Yarp.ReverseProxy.Transforms;

namespace Dantooine.BFF.Server
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        public void ConfigureServices(IServiceCollection services)
        {
            services.AddAntiforgery(options =>
            {
                options.HeaderName = "X-XSRF-TOKEN";
                options.Cookie.Name = "__Host-X-XSRF-TOKEN";
                options.Cookie.SameSite = SameSiteMode.Strict;
                options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
            });

            services.AddHttpClient();
            services.AddOptions();
            services.AddDataProtection()
                .PersistKeysToFileSystem(new DirectoryInfo("C:\\KeyRing"))
                .SetApplicationName("Demo");

            services.AddAuthentication(options =>
            {
                options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
            })
            .AddCookie(options =>
                {
                    options.LoginPath = "/api/Account/Login";
                    options.Cookie.Name = ".Demo.Identity";
                    options.Cookie.SameSite = SameSiteMode.None;
                    options.SlidingExpiration = false;
                    options.Cookie.MaxAge = TimeSpan.FromMinutes(15);
                    options.ExpireTimeSpan = TimeSpan.FromMinutes(15);
                })
            .AddOpenIdConnect(options =>
           {
               options.SignInScheme = "Cookies";
               options.Authority = "https://localhost:44319";
               options.ClientId = "blazorcodeflowpkceclient";
               options.ClientSecret = "codeflow_pkce_client_secret";
               options.RequireHttpsMetadata = true;
               options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
               options.ResponseType = OpenIdConnectResponseType.Code;
               options.UsePkce = true;
               options.SaveTokens = true;
               options.GetClaimsFromUserInfoEndpoint = true;
               options.UseTokenLifetime = true;
               options.SaveTokens = true;
               options.ClaimActions.MapAll();
               options.Scope.Clear();
               options.Scope.Add("openid");
               options.Scope.Add("profile");
               options.Scope.Add("roles");
               options.Scope.Add("email");
               options.Scope.Add("offline_access");
           });

            services.AddCors(o => o.AddPolicy("_myAllowSpecificOrigins",
                builder =>
                {
                    builder.AllowCredentials()
                        .WithOrigins(new[] { "https://localhost:44348", "https://localhost:44319" })
                        .SetIsOriginAllowedToAllowWildcardSubdomains()
                        .AllowAnyMethod()
                        .AllowAnyHeader();
                }));

            services.AddControllersWithViews(options =>
                 options.Filters.Add(new AutoValidateAntiforgeryTokenAttribute()));

            // Create an authorization policy used by YARP when forwarding requests
            // from the WASM application to the Dantooine.Api1 resource server.
            services.AddAuthorization(options => options.AddPolicy("CookieAuthenticationPolicy", builder =>
            {
                builder.AddAuthenticationSchemes(CookieAuthenticationDefaults.AuthenticationScheme);
                builder.RequireAuthenticatedUser();
            }));

            services.AddRazorPages();
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            app.UseCors("_myAllowSpecificOrigins");
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                app.UseWebAssemblyDebugging();
            }
            else
            {
                app.UseExceptionHandler("/Error");
            }

            app.UseSecurityHeaders(GetSecurityHeaderPolicy(env.IsDevelopment(),  "https://localhost:44319"));

            app.UseHttpsRedirection();
            app.UseBlazorFrameworkFiles();
            app.UseStaticFiles();

            app.UseRouting();
            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapRazorPages();
                endpoints.MapControllers();
                endpoints.MapFallbackToPage("/_Host");
            });
        }

        public static HeaderPolicyCollection GetSecurityHeaderPolicy(bool isDev, string idpHost)
        {
            var policy = new HeaderPolicyCollection()
                .AddFrameOptionsDeny()
                .AddXssProtectionBlock()
                .AddContentTypeOptionsNoSniff()
                .AddReferrerPolicyStrictOriginWhenCrossOrigin()
                .AddCrossOriginOpenerPolicy(builder => builder.SameOrigin())
                .AddCrossOriginResourcePolicy(builder => builder.SameOrigin())
                .AddCrossOriginEmbedderPolicy(builder => builder.RequireCorp())
                .AddContentSecurityPolicy(builder =>
                {
                    builder.AddObjectSrc().None();
                    builder.AddBlockAllMixedContent();
                    builder.AddImgSrc().Self().From("data:");
                    builder.AddFormAction().Self().From(idpHost);
                    builder.AddFontSrc().Self();
                    builder.AddStyleSrc().Self();
                    builder.AddBaseUri().Self();
                    builder.AddFrameAncestors().None();

                    builder.AddScriptSrc()
                        .Self()
                        .WithHash256("v8v3RKRPmN4odZ1CWM5gw80QKPCCWMcpNeOmimNL2AA=")
                        .UnsafeEval();
                });

            if (!isDev)
            {
                policy.AddStrictTransportSecurityMaxAgeIncludeSubDomains(maxAgeInSeconds: 60 * 60 * 24 * 365);
            }

            return policy;
        }
    }
}
