using System.Security.Claims;
using System.Threading.Tasks;
using Dantooine.Server.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Dantooine.Server.Areas.Identity
{
    public class CustomUserClaimsPrincipalFactory : UserClaimsPrincipalFactory<ApplicationUser>
    {
        public CustomUserClaimsPrincipalFactory(UserManager<ApplicationUser> userManager,
            IOptions<IdentityOptions> optionsAccessor) :
            base(userManager, optionsAccessor)
        {
        }

        protected override async Task<ClaimsIdentity> GenerateClaimsAsync(ApplicationUser user)
        {
            var claimsId = await base.GenerateClaimsAsync(user);
            claimsId.AddClaim(new Claim("acceptedPrivacy", user.AcceptedPrivacyPolicy.ToString()));
            return claimsId;
        }
    }
}
