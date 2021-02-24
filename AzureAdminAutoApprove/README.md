# Azure Function for SSO Connect Cloud Automated Device Approvals

This project implements [Azure Functions](https://azure.microsoft.com/en-us/services/functions/) that automatically approves all Keeper SSO Connect Cloud Admin Approval requests for users. It uses the [Keeper SDK .Net](https://github.com/Keeper-Security/keeper-sdk-dotnet-private) to communicate with the Keeper backend API.

Approvals can be started by:

 * timer (Timer Trigger)
 * web-hook  (HTTP Trigger)

### Timer
Azure Function name is `ApprovePendingRequestsByTimer`. This function is configured to be executed every minute.

### Web Hook
 Azure Function name is `ApprovePendingRequestsByWebHook`. This function requires function level authorization URL.
 Azure Function with name `KeeperConnectionGuard` should used along with the `ApprovePendingRequestsByWebHook`. 
 It just connects to the Keeper server to keep the session alive. It is executed every 12 hours, so make sure 
 the `Auto Logout` timeout for the Keeper accont is set to at least a day (or 1440 minutes)


### Instructions
See full installation instructions at our documentation portal:
https://docs.keeper.io/sso-connect-cloud/
