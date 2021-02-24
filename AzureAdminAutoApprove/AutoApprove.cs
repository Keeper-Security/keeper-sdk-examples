using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using System.Web.Http;
using KeeperSecurity.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.Extensions.Logging;

namespace AzureAdminAutoApprove
{
    public static class AutoApprove
    {

        [FunctionName("KeeperConnectionGuard")]
        public static async Task KeeperConnectionGuard(
            [TimerTrigger("12 12 */12 * * *")]
            TimerInfo myTimer,
            ILogger log)
        {
            using var auth = await ApproveUtils.ConnectToKeeper(log);
        }


        private const string AutoApproveWebHookAuthKey = "AutoApproveWebHookAuth";
        private const string HttpAuthenticationType = "Bearer";

        [FunctionName("ApprovePendingRequestsByWebHook")]
        public static async Task<IActionResult> ApprovePendingRequestsByWebHook(
            [HttpTrigger(AuthorizationLevel.Function, "POST", Route = null)]
            HttpRequest req,
            ILogger log)
        {

            var authHeader = req.Headers["Authorization"];
            if (authHeader.Count > 0)
            {
                var webHookAuth = Environment.GetEnvironmentVariable(AutoApproveWebHookAuthKey);
                if (string.IsNullOrEmpty(webHookAuth))
                {
                    log.LogError($"Rejected: Configuration required. Set {AutoApproveWebHookAuthKey} property.");
                    return new InternalServerErrorResult();
                }

                var matches = false;
                foreach (var authValue in authHeader)
                {
                    log.LogInformation($"Authorization: {authValue}");
                    if (authValue.StartsWith(HttpAuthenticationType, StringComparison.InvariantCultureIgnoreCase))
                    {
                        var token = authValue.Substring(HttpAuthenticationType.Length).Trim();
                        matches = token == webHookAuth;
                        if (matches) break;
                    }
                }

                if (!matches)
                {
                    log.LogError($"Rejected: Request is not authorized. Ensure {AutoApproveWebHookAuthKey} property matches request Auth token.");
                    return new UnauthorizedResult();
                }
            }

            var requestBody = await new StreamReader(req.Body).ReadToEndAsync();
            if (req.ContentType != "application/json")
            {
                log.LogWarning($"Expected: \"application/json\" content type. Got: {req.ContentType}");
            }

            using var auth = await ApproveUtils.ConnectToKeeper(log);
            var messages = new List<string>();
            await ApproveUtils.ExecuteDeviceApprove(auth, messages);
            foreach (var message in messages)
            {
                log.LogWarning(message);
            }

            return new OkResult();
        }


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
        public static async Task RunApproveQueuedTeams([TimerTrigger("0 */10 * * * *")]
            TimerInfo myTimer,
            ILogger log)
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
    }
}
