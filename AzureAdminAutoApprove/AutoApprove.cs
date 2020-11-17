using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using KeeperSecurity.Authentication;
using Microsoft.Azure.WebJobs;
using Microsoft.Extensions.Logging;

namespace AzureAdminAutoApprove
{
    public static class AutoApprove
    {
        [FunctionName("ApprovePendingRequestsByTimer")]
        public static async Task RunApprovePendingRequests([TimerTrigger("0 */1 * * * *")]
            TimerInfo myTimer,
            ILogger log)
        {
            log.LogInformation($"ApprovePendingRequestsByTimer trigger executed at: {DateTime.Now}");

            var messages = new List<string>();
            using var auth = await ApproveUtils.ConnectToKeeper(log);
            var approveStep = 0;
            bool Callback(NotificationEvent evt)
            {
                if (string.Compare(evt.Event, "request_device_admin_approval", StringComparison.InvariantCultureIgnoreCase) != 0) return false;
                log.LogInformation($"Received admin approval request for {evt.Email} at {evt.IPAddress}");

                Task.Run(async () =>
                {
                    try
                    {
                        var step = approveStep;
                        if (step > 0)
                        {
                            if (step == 1)
                            {
                                await Task.Delay(TimeSpan.FromSeconds(5));
                            }

                            await ApproveUtils.ExecuteDeviceApprove(auth, messages);
                        }
                    }
                    catch (Exception e)
                    {
                        messages.Add(e.Message);
                    }
                });

                return false;
            }
            auth.PushNotifications.RegisterCallback(Callback);

            await Task.Delay(TimeSpan.FromSeconds(5));
            approveStep = 1;
            await ApproveUtils.ExecuteDeviceApprove(auth, messages);
            approveStep = 2;

            await Task.Delay(TimeSpan.FromSeconds(30));
            auth.PushNotifications.RemoveCallback(Callback);
            await Task.Delay(TimeSpan.FromSeconds(5));

            foreach (var message in messages)
            {
                log.LogWarning(message);
            }
        }

        [FunctionName("ApproveQueuedTeamsByTimer")]
        public static async Task RunApproveQueuedTeams([TimerTrigger("0 */10 * * * *")] TimerInfo myTimer, ILogger log)
        {
            log.LogInformation($"ApproveQueuedTeamsByTimer trigger executed at: {DateTime.Now}");

            using var auth = await ApproveUtils.ConnectToKeeper(log);

            try
            {
                await ApproveUtils.ExecuteTeamApprove(auth, log);
            }
            catch (Exception e)
            {
                log.LogError(e, "ApproveQueuedTeamsByTimer");
            }

        }
        /*
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
        */
    }
}
