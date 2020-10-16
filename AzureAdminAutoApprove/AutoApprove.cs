using System;
using System.IO;
using System.Threading.Tasks;
using KeeperSecurity.Sdk;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.Extensions.Logging;

namespace AzureAdminAutoApprove
{
    public static class AutoApprove
    {
        /*
        [FunctionName("DebugInfo")]
        public static Task<IActionResult> DebugInfo(
            [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = null)]
            HttpRequest req,
            ILogger log)
        {
            log.LogInformation($"App Data Path: {Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData)}");

            var personalFolder = ApproveUtils.GetHomeFolder();
            if (!Directory.Exists(personalFolder))
            {
                Directory.CreateDirectory(personalFolder);
            }

            var filePath = Path.Combine(personalFolder, "test.json");
            File.WriteAllText(filePath, "OK");
            log.LogInformation($"Default file path: {filePath}");
            return Task.FromResult<IActionResult>(new OkResult());
        }
        */

        [FunctionName("ApprovePendingRequestsByTimer")]
        public static async Task Run([TimerTrigger("0 */1 * * * *")] TimerInfo myTimer, ILogger log)
        {
            log.LogInformation($"ApprovePendingRequestsByTimer trigger executed at: {DateTime.Now}");

            await ApproveUtils.ApprovePendingDevices(log);
        }


        [FunctionName("ApprovePendingRequestsByWebHook")]
        public static async Task<IActionResult> RunApprovePendingRequests(
            [HttpTrigger(AuthorizationLevel.Function, "GET", Route = null)]
            HttpRequest req,
            ILogger log)
        {
            log.LogInformation("HTTP trigger: ApprovePendingRequests.");

            try
            {
                await ApproveUtils.ApprovePendingDevices(log);
                return new OkObjectResult("Success");
            }
            catch (Exception e)
            {
                log.LogInformation(e.Message);
                return new ObjectResult(e.Message) {StatusCode = StatusCodes.Status400BadRequest};
            }
        }

        [FunctionName("AdminLoginConfiguration")]
        public static async Task<IActionResult> RunStoreLoginConfiguration(
            [HttpTrigger(AuthorizationLevel.Admin, "GET", "POST", Route = null)]
            HttpRequest req,
            ILogger log)
        {
            log.LogInformation($"HTTP trigger: {req.Method} StoreLoginConfiguration.");

            try
            {
                if (string.Compare(req.Method, "POST", StringComparison.InvariantCultureIgnoreCase) == 0)
                {

                    byte[] configData = null;
                    await using (var ms = new MemoryStream())
                    {
                        await req.Body.CopyToAsync(ms);
                        configData = ms.ToArray();
                    }

                    var jsonLoader = new InMemoryJsonConfiguration(configData);
                    var jsonCache = new JsonConfigurationCache(jsonLoader);
                    var newStorage = new JsonConfigurationStorage(jsonCache);
                    var auth = new Auth(new AuthUiNoAction(), newStorage);
                    try
                    {
                        auth.ResumeSession = true;
                        await auth.Login(newStorage.LastLogin);
                        jsonCache.Flush();
                        if (!auth.IsAuthenticated()) return new ObjectResult("Unexpected failure while to connecting to Keeper.") {StatusCode = StatusCodes.Status400BadRequest};
                        if (!auth.AuthContext.IsEnterpriseAdmin) return new ObjectResult($"{auth.AuthContext.Username} is not an enterprise admin.") {StatusCode = StatusCodes.Status401Unauthorized};

                        await File.WriteAllBytesAsync(ApproveUtils.GetKeeperConfigurationFilePath(), jsonLoader.Configuration);
                        return new OkObjectResult("Success");
                    }
                    catch (KeeperCanceled)
                    {
                        log.LogDebug("Invalid Keeper Configuration.");
                        return new ObjectResult("Failed to connect to Keeper") {StatusCode = StatusCodes.Status400BadRequest};
                    }
                }

                var fileName = ApproveUtils.GetKeeperConfigurationFilePath();
                if (!File.Exists(fileName))
                {
                    log.LogDebug("Keeper Configuration is not loaded yet.");
                    return new ObjectResult("Keeper Configuration is not loaded yet") { StatusCode = StatusCodes.Status404NotFound };
                }

                
                var configBody = await File.ReadAllBytesAsync(fileName);

                return new FileContentResult(configBody, "application/json");
            }
            catch (Exception e)
            {
                log.LogDebug(e.Message);
                return new ObjectResult(e.Message) {StatusCode = StatusCodes.Status500InternalServerError};
            }
        }
    }
}
