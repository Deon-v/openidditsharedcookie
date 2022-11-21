using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Quartz;
using Dantooine.Server.Data;
using static OpenIddict.Abstractions.OpenIddictConstants;
using Microsoft.IdentityModel.Logging;
using Dantooine.Server.Areas.Identity;
using Microsoft.AspNetCore.Authentication.Cookies;
using System.Configuration;
using System;
using System.IO;
using Microsoft.AspNetCore.Http;
using Humanizer.Configuration;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using System.Text.Json;
using OpenIddict.Validation.AspNetCore;
using FastEndpoints;

namespace Dantooine.Server;

public class Startup
{
    public Startup(IConfiguration configuration)
        => Configuration = configuration;

    public IConfiguration Configuration { get; }

    public void ConfigureServices(IServiceCollection services)
    {
        
    }

    public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
    {
        
    }
}
