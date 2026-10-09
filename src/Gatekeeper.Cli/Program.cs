using Gatekeeper.Cli;

var http = (Uri baseUrl) => new HttpClient { BaseAddress = baseUrl, Timeout = TimeSpan.FromSeconds(30) };
return await CliApp.RunAsync(args, http, Console.Out, Console.Error);
