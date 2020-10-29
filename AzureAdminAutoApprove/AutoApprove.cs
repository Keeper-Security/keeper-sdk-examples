using System;
using System.Threading.Tasks;
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
            var path = ApproveUtils.GetKeeperConfigurationFilePath();
            var attr = System.IO.File.GetAttributes(path);
            if ((attr & FileAttributes.Directory) != 0)
            {
                Directory.Delete(path);
            }
            return Task.FromResult<IActionResult>(new OkResult());
        }
        */
        [FunctionName("ApprovePendingRequestsByTimer")]
        public static async Task RunApprovePendingRequests([TimerTrigger("0 */1 * * * *")] TimerInfo myTimer, ILogger log)
        {
            log.LogInformation($"ApprovePendingRequestsByTimer trigger executed at: {DateTime.Now}");

            var auth = await ApproveUtils.ConnectToKeeper(log, true);
            auth.AuthContext.PushNotifications.RegisterCallback(ApproveUtils.NotificationCallback);
            await ApproveUtils.ExecuteDeviceApprove(auth);

            await Task.Delay(TimeSpan.FromSeconds(30));
        }

        [FunctionName("ApproveQueuedTeamsByTimer")]
        public static async Task RunApproveQueuedTeams([TimerTrigger("0 */10 * * * *")] TimerInfo myTimer, ILogger log)
        {
            log.LogInformation($"ApproveQueuedTeamsByTimer trigger executed at: {DateTime.Now}");

            try
            {
                var auth = await ApproveUtils.ConnectToKeeper(log, false);
                await ApproveUtils.ExecuteTeamApprove(auth);
            }
            catch (Exception e)
            {
                log.LogError(e, "ApproveQueuedTeamsByTimer");
            }

        }

        [FunctionName("DumpPendingMessages")]
        public static Task<IActionResult> RunDumpPendingMessages(
            [HttpTrigger(AuthorizationLevel.Function, "get", Route = null)]
            HttpRequest req,
            ILogger log)
        {
            log.LogInformation("HTTP trigger: ApprovePendingRequests.");

            while (!ApproveUtils.Errors.IsEmpty)
            {
                if (ApproveUtils.Errors.TryTake(out var message))
                {
                    log.LogInformation(message);
                }
                else
                {
                    break;
                }
            }

            return Task.FromResult<IActionResult>( new OkObjectResult("Success"));
        }
    }
}
