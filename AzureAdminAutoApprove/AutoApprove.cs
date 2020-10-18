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
        public static async Task Run([TimerTrigger("0 */1 * * * *")]
            TimerInfo myTimer,
            ILogger log)
        {
            log.LogInformation($"ApprovePendingRequestsByTimer trigger executed at: {DateTime.Now}");

            await ApproveUtils.ApprovePendingDevices();
            await Task.Delay(TimeSpan.FromSeconds(30));
        }

        [FunctionName("ApprovePendingRequestsByWebHook")]
        public static async Task<IActionResult> RunApprovePendingRequests(
            [HttpTrigger(AuthorizationLevel.Function, "get", Route = null)]
            HttpRequest req,
            ILogger log)
        {
            log.LogInformation("HTTP trigger: ApprovePendingRequests.");

            try
            {
                await ApproveUtils.ExecuteDeviceApprove();

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

                return new OkObjectResult("Success");
            }
            catch (Exception e)
            {
                log.LogInformation(e.Message);
                return new ObjectResult(e.Message) {StatusCode = StatusCodes.Status400BadRequest};
            }
        }
    }
}
