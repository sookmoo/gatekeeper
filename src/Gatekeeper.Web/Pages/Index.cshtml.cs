using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Gatekeeper.Web.Pages;

public class IndexModel : PageModel
{
    public IActionResult OnPost() => NotFound();

    public IActionResult OnGet() => RedirectToPage("/Applications/Index");
}
