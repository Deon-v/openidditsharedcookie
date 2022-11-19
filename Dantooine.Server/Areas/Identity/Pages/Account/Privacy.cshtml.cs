using Dantooine.Server.Data;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions;
using OpenIddict.EntityFrameworkCore.Models;
using System;
using System.Threading.Tasks;

namespace Dantooine.Server.Areas.Identity.Pages.Account
{
    [Authorize(AuthenticationSchemes = CookieAuthenticationDefaults.AuthenticationScheme)]
    public class PrivacyModel : PageModel
    {
        private readonly ILogger<PrivacyModel> _logger;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly IOpenIddictApplicationManager _openIddictApplicationManager;

        public PrivacyModel(ILogger<PrivacyModel> logger, UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager, IOpenIddictApplicationManager openIddictApplicationManager)
        {
            _logger = logger;
            _userManager = userManager;
            _signInManager = signInManager;
            _openIddictApplicationManager = openIddictApplicationManager;
        }

        [BindProperty] public bool Accept { get; set; }

        public string ClientId { get; set; }

        public async Task<IActionResult> OnGetAsync(string? clientId = null)
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null) return Unauthorized();
            ClientId = clientId;
            return Page();
        }

        public async Task<IActionResult> OnPostAcceptAsync(string? clientId = null)
        {
            if (clientId != null)
            {
                string returnUrl = await GetClientUrl(clientId);

                var user = await _userManager.GetUserAsync(User);
                user.AcceptedPrivacyPolicy = true;
                await _userManager.UpdateAsync(user);
                await _signInManager.RefreshSignInAsync(user);
                return Redirect(returnUrl);
            }

            await _signInManager.SignOutAsync();
            return RedirectToPage("./Login");
        }

        public async Task<IActionResult> OnPostRejectAsync(string? clientId = null)
        {
            if (clientId != null)
            {
                var user = await _userManager.GetUserAsync(User);
                user.AcceptedPrivacyPolicy = false;
                await _userManager.UpdateAsync(user);
            }

            await _signInManager.SignOutAsync();
            return RedirectToPage("./Login");
        }

        private async Task<string> GetClientUrl(string clientId)
        {
            var application = (await _openIddictApplicationManager.FindByClientIdAsync(clientId)) as OpenIddictEntityFrameworkCoreApplication;

            string urls = application.RedirectUris;
            char[] separators = new char[] { '[', ']', '"' };
            foreach (char c in separators)
            {
                urls = urls.Replace(c, '\n');
            }

            var uri = new Uri(urls);

            return $"{uri.Scheme}://{uri.Authority}/";
        }
    }
}
