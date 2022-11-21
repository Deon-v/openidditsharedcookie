using Dantooine.Server.Areas.Identity;
using Dantooine.Server.Data;
using FastEndpoints;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Validation.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;
using System.Configuration;
using System.IO;
using System;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Quartz;
using Microsoft.Extensions.Options;
using System.Text;
using FastEndpoints.Security;

namespace Dantooine.Server;

public static class Program
{
    public static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);

        var app = builder.ConfigureServices();
        app.ConfigureApplication()?.Run();
    }

    public static WebApplication? ConfigureServices(this WebApplicationBuilder builder)
    {
        var services = builder.Services;
        var Configuration = builder.Configuration;

        services.AddControllersWithViews();
        services.AddRazorPages();
        services.AddFastEndpoints();
        //services.AddAuthenticationJWTBearer("DRjd/GnduI3Efzen9V9BvbNUfc/VKgXltV7Kbk9sMkY=");

        services.ConfigureApplicationCookie(options =>
        {
            options.Cookie.Name = ".Demo.Identity";
        });

        services.AddDataProtection()
            .PersistKeysToFileSystem(new DirectoryInfo("C:\\KeyRing"))
            .SetApplicationName("Demo");

        services.AddSession(options =>
        {
            options.Cookie.Name = "Synth.Auth";
            options.IdleTimeout = TimeSpan.FromMinutes(2);
            options.Cookie.HttpOnly = true;
            options.Cookie.SameSite = SameSiteMode.None;
            options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
        });

        services.AddDbContext<ApplicationDbContext>(options =>
        {
            // Configure the context to use Microsoft SQL Server.
            options.UseSqlServer(Configuration.GetConnectionString("DefaultConnection"));

            // Register the entity sets needed by OpenIddict.
            // Note: use the generic overload if you need
            // to replace the default OpenIddict entities.
            options.UseOpenIddict();
        });

        services.AddDatabaseDeveloperPageExceptionFilter();

        // Register the Identity services.
        services.AddIdentity<ApplicationUser, IdentityRole>()
            .AddEntityFrameworkStores<ApplicationDbContext>()
            .AddDefaultTokenProviders()
            .AddDefaultUI();

        services.Configure<IdentityOptions>(options =>
        {
            // Configure Identity to use the same JWT claims as OpenIddict instead
            // of the legacy WS-Federation claims it uses by default (ClaimTypes),
            // which saves you from doing the mapping in your authorization controller.
            options.ClaimsIdentity.UserNameClaimType = Claims.Name;
            options.ClaimsIdentity.UserIdClaimType = Claims.Subject;
            options.ClaimsIdentity.RoleClaimType = Claims.Role;
            options.ClaimsIdentity.EmailClaimType = Claims.Email;
        });

        services.AddScoped<IUserClaimsPrincipalFactory<ApplicationUser>, CustomUserClaimsPrincipalFactory>();

        // OpenIddict offers native integration with Quartz.NET to perform scheduled tasks
        // (like pruning orphaned authorizations/tokens from the database) at regular intervals.
        services.AddQuartz(options =>
        {
            options.UseMicrosoftDependencyInjectionJobFactory();
            options.UseSimpleTypeLoader();
            options.UseInMemoryStore();
        });

        services.AddCors(options =>
        {
            options.AddPolicy("AllowAllOrigins",
                builder =>
                {
                    builder
                        .AllowCredentials()
                        .WithOrigins(new[] { "https://localhost:44348", "https://localhost:44319" })
                        .SetIsOriginAllowedToAllowWildcardSubdomains()
                        .AllowAnyHeader()
                        .AllowAnyMethod();
                });
        });

        // Register the Quartz.NET service and configure it to block shutdown until jobs are complete.
        services.AddQuartzHostedService(options => options.WaitForJobsToComplete = true);

        services.AddAuthentication(OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme)
            .AddCookie(options =>
            {
                options.LoginPath = "/Identity/Account/Login";
                options.Cookie.Name = ".Demo.Identity";
                options.Cookie.SameSite = SameSiteMode.None;
                options.SlidingExpiration = false;
                options.Cookie.MaxAge = TimeSpan.FromMinutes(15);
                options.ExpireTimeSpan = TimeSpan.FromMinutes(15);
            }); 
        services.AddAuthorization();

        services.AddOpenIddict()
            // Register the OpenIddict core components.
            .AddCore(options =>
            {
                // Configure OpenIddict to use the Entity Framework Core stores and models.
                // Note: call ReplaceDefaultEntities() to replace the default OpenIddict entities.
                options.UseEntityFrameworkCore()
                       .UseDbContext<ApplicationDbContext>();

                // Enable Quartz.NET integration.
                options.UseQuartz();
            })
            // Register the OpenIddict server components.
            .AddServer(options =>
            {
                options.SetAccessTokenLifetime(TimeSpan.FromMinutes(15))
                    .SetIdentityTokenLifetime(TimeSpan.FromMinutes(15))
                    .SetRefreshTokenLifetime(TimeSpan.FromMinutes(15));

                // Enable the authorization, logout, token and userinfo endpoints.
                options.SetAuthorizationEndpointUris("/connect/authorize")
                       .SetLogoutEndpointUris("/connect/logout")
                       .SetIntrospectionEndpointUris("/connect/introspect")
                       .SetTokenEndpointUris("/connect/token")
                       .SetUserinfoEndpointUris("/connect/userinfo")
                       .SetVerificationEndpointUris("/connect/verify");

                // Mark the "email", "profile" and "roles" scopes as supported scopes.
                options.RegisterScopes(Scopes.Email, Scopes.Profile, Scopes.Roles);

                // Note: this sample only uses the authorization code flow but you can enable
                // the other flows if you need to support implicit, password or client credentials.
                options.AllowAuthorizationCodeFlow()
                    .AllowHybridFlow()
                    .AllowClientCredentialsFlow()
                    .AllowRefreshTokenFlow();

                // Register the signing and encryption credentials.
                options.AddEncryptionKey(new SymmetricSecurityKey(
                        Convert.FromBase64String("DRjd/GnduI3Efzen9V9BvbNUfc/VKgXltV7Kbk9sMkY=")));
                options.AddDevelopmentSigningCertificate();

                // Register the ASP.NET Core host and configure the ASP.NET Core-specific options.
                options.UseAspNetCore()
                       .EnableAuthorizationEndpointPassthrough()
                       .EnableLogoutEndpointPassthrough()
                       .EnableTokenEndpointPassthrough()
                       .EnableUserinfoEndpointPassthrough()
                       .EnableStatusCodePagesIntegration();
            })
            // Register the OpenIddict validation components.
            .AddValidation(options =>
            {
                //// Note: the validation handler uses OpenID Connect discovery
                //// to retrieve the issuer signing keys used to validate tokens.
                options.SetIssuer("https://localhost:44319/");
                ////options.AddAudiences("resource_server_2");

                //// Register the encryption credentials. This sample uses a symmetric
                //// encryption key that is shared between the server and the Api2 sample
                //// (that performs local token validation instead of using introspection).
                ////
                //// Note: in a real world application, this encryption key should be
                //// stored in a safe place (e.g in Azure KeyVault, stored as a secret).
                options.AddEncryptionKey(new SymmetricSecurityKey(
                    Convert.FromBase64String("DRjd/GnduI3Efzen9V9BvbNUfc/VKgXltV7Kbk9sMkY=")));

                //// Register the System.Net.Http integration.
                options.UseSystemNetHttp();
                // Import the configuration from the local OpenIddict server instance.
                //options.UseLocalServer();

                // Register the ASP.NET Core host.
                options.UseAspNetCore();
            });

        // Register the worker responsible for seeding the database.
        // Note: in a real world application, this step should be part of a setup script.
        services.AddHostedService<Worker>();
        return builder.Build();
        }

    public static WebApplication? ConfigureApplication(this WebApplication? app)
    {
        IdentityModelEventSource.ShowPII = true;

        if (app.Environment.IsDevelopment())
        {
            app.UseDeveloperExceptionPage();
            app.UseMigrationsEndPoint();
        }
        else
        {
            app.UseStatusCodePagesWithReExecute("~/error");
            //app.UseExceptionHandler("~/error");

            // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
            //app.UseHsts();
        }

        app.UseCors("AllowAllOrigins");
        app.UseHttpsRedirection();
        app.UseStaticFiles();

        app.UseRouting();

        app.UseAuthentication();
        app.UseAuthorization();
        app.UseSession();

        app.UseFastEndpoints();

        app.MapControllers();
        app.MapDefaultControllerRoute();
        app.MapRazorPages();
        
        return app;
    }
}
