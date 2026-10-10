using Gatekeeper.Cli;

var http = (Uri baseUrl) => new HttpClient { BaseAddress = baseUrl, Timeout = TimeSpan.FromSeconds(30), MaxResponseContentBufferSize = 4 * 1024 * 1024 };
return await CliApp.RunAsync(args, http, Console.Out, Console.Error);
