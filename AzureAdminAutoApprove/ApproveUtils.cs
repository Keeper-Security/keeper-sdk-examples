using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Authentication;
using Enterprise;
using Google.Protobuf;
using KeeperSecurity.Sdk;
using KeeperSecurity.Sdk.UI;
using Org.BouncyCastle.Crypto.Parameters;

namespace AzureAdminAutoApprove
{
    internal static class ApproveUtils
    {
        private static Auth _auth;
        private static ECPrivateKeyParameters _enterprisePrivateKey;

        static ApproveUtils()
        {
            _auth = null;
            _enterprisePrivateKey = null;
        }


        public static string GetHomeFolder()
        {
            var path = Path.Combine(Environment.GetEnvironmentVariable("HOME") ?? Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), ".keeper");
            if (!Directory.Exists(path))
            {
                Directory.CreateDirectory(path);
            }

            return path;
        }

        public static string GetKeeperConfigurationFilePath()
        {
            return Path.Combine(GetHomeFolder(), "config.json");
        }

        private static readonly SemaphoreSlim Semaphore = new SemaphoreSlim(1);

        private static bool NotificationCallback(NotificationEvent evt)
        {
            if (string.Compare(evt.Event, "request_device_admin_approval", StringComparison.InvariantCultureIgnoreCase) != 0) return false;
            Errors.Add("Received admin approval request");
            Task.Run(async () =>
            {
                try
                {
                    await ExecuteDeviceApprove();
                }
                catch (Exception e)
                {
                    Errors.Add($"Process request error: {e.Message}");
                }
            });
            return false;
        }

        public static readonly ConcurrentBag<string> Errors = new ConcurrentBag<string>();
        public static async Task ExecuteDeviceApprove()
        {
            Auth auth;
            if (!await Semaphore.WaitAsync(TimeSpan.FromSeconds(10))) throw new Exception("Timed out");
            try
            {
                auth = _auth;
                if (auth == null || !auth.IsAuthenticated())
                {
                    Errors.Add("Not connected to Keeper");
                }
            }
            finally
            {
                Semaphore.Release();
            }
            var keysRq = new EnterpriseDataCommand
            {
                include = new[] { "devices_request_for_admin_approval" }
            };
            var rs = await _auth.ExecuteAuthCommand<EnterpriseDataCommand, EnterpriseDataResponse>(keysRq);
            if ((rs.DeviceRequestForApproval?.Count ?? 0) == 0) return;

            var userDataKeys = new Dictionary<long, byte[]>();
            foreach (var drq in rs.DeviceRequestForApproval)
            {
                if (!userDataKeys.ContainsKey(drq.EnterpriseUserId))
                {
                    userDataKeys[drq.EnterpriseUserId] = null;
                }
            }

            var dataKeyRq = new UserDataKeyRequest();
            dataKeyRq.EnterpriseUserId.AddRange(userDataKeys.Keys);
            var dataKeyRs = await auth.ExecuteAuthRest<UserDataKeyRequest, EnterpriseUserDataKeys>("enterprise/get_enterprise_user_data_key", dataKeyRq);
            foreach (var key in dataKeyRs.Keys)
            {
                if (key.UserEncryptedDataKey.IsEmpty) continue;
                //if (KeyType.Ecc.CompareTo(key.KeyTypeId) == 0) { }
                try
                {
                    var userDataKey = CryptoUtils.DecryptEc(key.UserEncryptedDataKey.ToByteArray(), _enterprisePrivateKey);
                    userDataKeys[key.EnterpriseUserId] = userDataKey;
                }
                catch (Exception e)
                {
                    Errors.Add($"Data key decrypt error: {e.Message}");
                }
            }

            var approveDevicesRq = new ApproveUserDevicesRequest();
            foreach (var drq in rs.DeviceRequestForApproval)
            {
                if (!userDataKeys.ContainsKey(drq.EnterpriseUserId) || userDataKeys[drq.EnterpriseUserId] == null) continue;

                var dataKey = userDataKeys[drq.EnterpriseUserId];
                var devicePublicKey = CryptoUtils.LoadPublicEcKey(drq.DevicePublicKey.Base64UrlDecode());
                var encDataKey = CryptoUtils.EncryptEc(dataKey, devicePublicKey);
                var approveRq = new ApproveUserDeviceRequest
                {
                    EnterpriseUserId = drq.EnterpriseUserId,
                    EncryptedDeviceToken = ByteString.CopyFrom(drq.EncryptedDeviceToken.Base64UrlDecode()),
                    EncryptedDeviceDataKey = ByteString.CopyFrom(encDataKey),
                    DenyApproval = false,
                };
                approveDevicesRq.DeviceRequests.Add(approveRq);
            }
            if (approveDevicesRq.DeviceRequests.Count == 0) return;

            var approveRs = await auth.ExecuteAuthRest<ApproveUserDevicesRequest, ApproveUserDevicesResponse>("enterprise/approve_user_devices", approveDevicesRq);
            foreach (var deviceRs in approveRs.DeviceResponses)
            {
                if (deviceRs.Failed)
                {
                    Errors.Add($"Data key approval failed: {deviceRs.EnterpriseUserId}: {deviceRs.Message}");
                }
                else
                {
                    Errors.Add($"Successfully approved: {deviceRs.EnterpriseUserId}");
                }
            }
        }

        public static async Task ApprovePendingDevices()
        {
            if (!await Semaphore.WaitAsync(TimeSpan.FromSeconds(10))) throw new Exception("Timed out");
            try
            {
                if (_auth != null)
                {
                    if (_auth.IsAuthenticated())
                    {
                        _auth.AuthContext.PushNotifications.Shutdown();
                    }

                    _auth = null;
                }

                var configPath = GetKeeperConfigurationFilePath();
                var jsonCache = new JsonConfigurationCache(new JsonConfigurationFileLoader(configPath));
                var jsonConfiguration = new JsonConfigurationStorage(jsonCache);
                _auth = new Auth(new AuthUiNoAction(), jsonConfiguration)
                {
                    ResumeSession = true
                };
                await _auth.Login(jsonConfiguration.LastLogin);
                jsonCache.Flush();

                var keysRq = new EnterpriseDataCommand
                {
                    include = new[] { "keys" }
                };
                var rs = await _auth.ExecuteAuthCommand<EnterpriseDataCommand, EnterpriseDataResponse>(keysRq);
                if (string.IsNullOrEmpty(rs.Keys?.EccEncryptedPrivateKey))
                {
                    throw new Exception("Enterprise does not have EC key pair");
                }

                var encTreeKey = rs.TreeKey.Base64UrlDecode();
                var treeKey = rs.KeyTypeId switch
                {
                    1 => CryptoUtils.DecryptAesV1(encTreeKey, _auth.AuthContext.DataKey),
                    2 => CryptoUtils.DecryptRsa(encTreeKey, _auth.AuthContext.PrivateKey),
                    _ => throw new Exception("cannot decrypt tree key")
                };

                var privateKeyData = CryptoUtils.DecryptAesV2(rs.Keys.EccEncryptedPrivateKey.Base64UrlDecode(), treeKey);
                _enterprisePrivateKey = CryptoUtils.LoadPrivateEcKey(privateKeyData);

                _auth.AuthContext.PushNotifications.RegisterCallback(NotificationCallback);
            }
            catch
            {
                _auth = null;
                throw;
            }
            finally
            {
                Semaphore.Release();
            }

            try
            {
                await ExecuteDeviceApprove();
            }
            catch (Exception e)
            {
               Errors.Add($"Device approve error: {e.Message}");
            }

        }
    }

    internal class AuthUiNoAction : IAuthUI
    {
        public Task<bool> WaitForDeviceApproval(IDeviceApprovalChannelInfo[] channels, CancellationToken token)
        {
            return Task.FromResult(false);
        }

        public Task<bool> WaitForTwoFactorCode(ITwoFactorChannelInfo[] channels, CancellationToken token)
        {
            return Task.FromResult(false);
        }

        public Task<bool> WaitForUserPassword(IPasswordInfo passwordInfo, CancellationToken token)
        {
            return Task.FromResult(false);
        }
    }
}
