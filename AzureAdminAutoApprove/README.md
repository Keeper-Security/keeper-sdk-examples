# Auto Approve Admin Approval requests for SSO user's datakey 

 This project implements [Azure Functions](https://azure.microsoft.com/en-us/services/functions/) that automatically approves all Admin Approval requests for datakey.
 It uses [Keeper SDK .Net](https://github.com/Keeper-Security/keeper-sdk-dotnet-private) to work with Keeper.


 Approval can be started by 

 * timer (Timer Trigger)
 * web-hook  (HTTP Trigger)

 ### Timer
  Azure Function name is `ApprovePendingRequestsByTimer`. This function is configured to be executed every minute.

 ### Web Hook
  Azure Function name is `ApprovePendingRequestsByWebHook`. This function requires function level authorization URL.

 ### Instructions

 [Quickstart guide to Azure Functions developpment](https://docs.microsoft.com/en-us/azure/azure-functions/functions-create-your-first-function-visual-studio)

 Once this project is successfully deployed to the Azure Cloud we need to upload Keeper configuration prepared for [persistent login](https://keeper.atlassian.net/wiki/spaces/KA/pages/903250019/V3+Login+Process)
 
 Use [.Net Commander](https://github.com/Keeper-Security/keeper-sdk-dotnet-private/tree/master/Commander) to create Keeper configuration.

 1. Create empty JSON configuration file. file name `config.json` content `{}`
 2. Start Commander.exe
 3. Login to your Enterprise Admin Account 
    - `login <email address>`
 4. Provision Keeper configuration for persistent login: 
    - `this-device register`
    - `this-device persistent_login on`
    - `this-device timeout 2880`   session timeout to 2 days
5. Ensure this configuration supports persistent login
    - Close Commander `q`. Do not run `logout` command
    - Start Commander.exe. You should be able to login with no input.
    
Use `KeeperLoginConfiguration` function to upload Keeper configuration
This is `HTTP trigger` function that supports GET and POST methods. 
* GET returns the current Keeper configuration
* POST uploads the new one
This function requires admin level authorization.

`curl -d @config.json <KeeperLoginConfiguration URL for administrator>` 

It returns `Success` if configuration is accepted.

