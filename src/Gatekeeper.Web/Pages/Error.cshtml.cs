using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Gatekeeper.Web.Pages;

/// <summary>Shown for status codes without a page of their own. Only fixed texts, chosen by the status code: nothing is echoed.</summary>
[IgnoreAntiforgeryToken] // re-executed for failed POSTs too, and it changes nothing
public class ErrorModel : PageModel
{
    public string Heading { get; private set; } = "Something went wrong";
    public string Text { get; private set; } = "Please try again.";

    public void OnPost(int? code) => OnGet(code);

    public void OnGet(int? code)
    {
        (Heading, Text) = code switch
        {
            400 => ("The request was not accepted", "The form may have expired. Go back, reload the page and try again."),
            403 => ("Not allowed", "You are not allowed to do that."),
            404 => ("Not found", "This page or item does not exist (it may already have been deleted)."),
            429 => ("Too many attempts", "Try again later."),
            _ => ("Something went wrong", "Please try again."),
        };
    }
}
