using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using FastEndpoints;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using OpenIddict.Validation.AspNetCore;

namespace Dantooine.Server.DirectApi;

//[Authorize(AuthenticationSchemes = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme)]
public sealed class DriectApiEndpoint : EndpointWithoutRequest<IEnumerable<string>>
{
    public DriectApiEndpoint()
    {

    }

    public override void Configure()
    {
        Get("api/test/DirectApi");
        AuthSchemes(OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme);
        //AuthSchemes(JwtBearerDefaults.AuthenticationScheme);
        //AllowAnonymous();//Roles("");
    }

    public override async Task HandleAsync(CancellationToken ct)
    {
        await SendAsync(new List<string> { "some data", "more data", "loads of data" }, default, ct);
    }
}