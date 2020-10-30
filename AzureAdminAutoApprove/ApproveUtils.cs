using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Authentication;
using Enterprise;
using Google.Protobuf;
using KeeperSecurity.Sdk;
using KeeperSecurity.Sdk.UI;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Crypto.Parameters;

namespace AzureAdminAutoApprove
{
    internal static class ApproveUtils
    {
        private static ECPrivateKeyParameters _enterprisePrivateKey;

        static ApproveUtils()
        {
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


        private static async Task<List<KeeperApiResponse>> ExecuteCommands(this IAuthentication auth, IReadOnlyCollection<KeeperApiCommand> commands)
        {
            var responses = new List<KeeperApiResponse>();
            var pos = 0;
            while (pos < commands.Count)
            {
                var executeRq = new ExecuteCommand
                {
                    Requests = commands.Skip(pos).Take(99).ToArray()
                };
                pos += 99;

                var executeRs = await auth.ExecuteAuthCommand<ExecuteCommand, ExecuteResponse>(executeRq);
                responses.AddRange(executeRs.Results);
                if (responses.Count < pos)
                {
                    break;
                }

                await Task.Delay(TimeSpan.FromSeconds(10));
            }

            return responses;
        }

        public static async Task ExecuteTeamApprove(Auth auth, ILogger log)
        {
            var teamRq = new EnterpriseDataCommand
            {
                include = new[] {"queued_teams"}
            };
            var teamRs = await auth.ExecuteAuthCommand<EnterpriseDataCommand, EnterpriseDataResponse>(teamRq);

            var encTreeKey = teamRs.TreeKey.Base64UrlDecode();
            var treeKey = teamRs.KeyTypeId switch
            {
                1 => CryptoUtils.DecryptAesV1(encTreeKey, auth.AuthContext.DataKey),
                2 => CryptoUtils.DecryptRsa(encTreeKey, auth.AuthContext.PrivateKey),
                _ => throw new Exception("cannot decrypt tree key")
            };

            if (teamRs.QueuedTeams?.Count > 0)
            {
                var commands = new List<TeamAddCommand>();
                foreach (var qt in teamRs.QueuedTeams)
                {
                    var teamKey = CryptoUtils.GenerateEncryptionKey();
                    CryptoUtils.GenerateRsaKey(out var privateKey, out var publicKey);
                    var cmd = new TeamAddCommand
                    {
                        TeamUid = qt.TeamUid,
                        TeamName = qt.Name,
                        RestrictEdit = false,
                        RestrictShare = false,
                        RestrictView = false,
                        PublicKey = publicKey.Base64UrlEncode(),
                        PrivateKey = CryptoUtils.EncryptAesV1(privateKey, teamKey).Base64UrlEncode(),
                        NodeId = qt.NodeId,
                        TeamKey = CryptoUtils.EncryptAesV1(teamKey, auth.AuthContext.DataKey).Base64UrlEncode(),
                        ManageOnly = true,
                        EncryptedTeamKey = CryptoUtils.EncryptAesV2(teamKey, treeKey).Base64UrlEncode()
                    };
                    commands.Add(cmd);
                }

                var responses = await auth.ExecuteCommands(commands);
            }

            var userRq = new EnterpriseDataCommand
            {
                include = new[] {"teams", "users", "queued_team_users"}
            };
            var userRs = await auth.ExecuteAuthCommand<EnterpriseDataCommand, EnterpriseDataResponse>(userRq);
            if (userRs.QueuedTeamUsers?.Count > 0)
            {
                var userLookup = new Dictionary<long, EnterpriseUser>();
                if (userRs.Users != null)
                {
                    foreach (var u in userRs.Users.Where(x => x.Status == "active"))
                    {
                        userLookup[u.EnterpriseUserId] = u;
                    }
                }

                var usersToApprove = new HashSet<long>();
                var teams = new HashSet<string>();
                foreach (var qtu in userRs.QueuedTeamUsers.Where(x => x.Users != null))
                {
                    usersToApprove.UnionWith(qtu.Users);
                }

                usersToApprove.IntersectWith(userLookup.Keys);
                if (usersToApprove.Count > 0)
                {
                    foreach (var qtu in userRs.QueuedTeamUsers.Where(x => x.Users != null))
                    {
                        if (usersToApprove.Overlaps(qtu.Users))
                        {
                            teams.Add(qtu.TeamUid);
                        }
                    }

                    if (userRs.Teams?.Count > 0)
                    {
                        teams.IntersectWith(userRs.Teams.Select(x => x.TeamUid));
                    }
                }

                if (usersToApprove.Count > 0 && teams.Count > 0)
                {
                    var teamKeys = new Dictionary<string, byte[]>();
                    if (userRs.Teams?.Count > 0)
                    {
                        foreach (var t in userRs.Teams)
                        {
                            if (!teams.Contains(t.TeamUid)) continue;
                            if (string.IsNullOrEmpty(t.EncryptedTeamKey)) continue;
                            try
                            {
                                teamKeys[t.TeamUid] = CryptoUtils.DecryptAesV2(t.EncryptedTeamKey.Base64UrlDecode(), treeKey);
                            }
                            catch
                            {
                                // ignore
                            }
                        }
                    }

                    var tgk = teams.Where(x => !teamKeys.ContainsKey(x)).Take(90).ToArray();
                    if (tgk.Any())
                    {
                        var teamKeyRq = new TeamGetKeysCommand
                        {
                            teams = tgk
                        };
                        var teamKeyRs = await auth.ExecuteAuthCommand<TeamGetKeysCommand, TeamGetKeysResponse>(teamKeyRq);
                        if (teamKeyRs.TeamKeys?.Length > 0)
                        {
                            foreach (var tk in teamKeyRs.TeamKeys)
                            {
                                if (string.IsNullOrEmpty(tk.Key)) continue;
                                try
                                {
                                    switch (tk.KeyType)
                                    {
                                        case 1:
                                            teamKeys[tk.TeamUID] = CryptoUtils.DecryptAesV1(tk.Key.Base64UrlDecode(), auth.AuthContext.DataKey);
                                            break;
                                        case 2:
                                            teamKeys[tk.TeamUID] = CryptoUtils.DecryptRsa(tk.Key.Base64UrlDecode(), auth.AuthContext.PrivateKey);
                                            break;
                                    }
                                }
                                catch
                                {
                                    // ignored
                                }
                            }
                        }
                    }

                    var userKeys = new Dictionary<string, byte[]>(StringComparer.InvariantCultureIgnoreCase);
                    var emails = usersToApprove
                        .Select(x => userLookup.TryGetValue(x, out var u) ? u : null )
                        .Where(x => x != null)
                        .Select(x => x.Username)
                        .Take(99)
                        .ToArray();
                    var userKeyRq = new PublicKeysCommand
                    {
                        key_owners = emails
                    };
                    var userKeyRs = await auth.ExecuteAuthCommand<PublicKeysCommand, PublicKeyResponse>(userKeyRq);
                    if (userKeyRs.PublicKeys?.Length > 0)
                    {
                        foreach (var uk in userKeyRs.PublicKeys)
                        {
                            if (!string.IsNullOrEmpty(uk.UserName) && !string.IsNullOrEmpty(uk.PublicKey))
                            {
                                userKeys[uk.UserName] = uk.PublicKey.Base64UrlDecode();
                            }
                        }
                    }

                    var commands = new List<TeamEnterpriseUserAddCommand>();
                    foreach (var qtu in userRs.QueuedTeamUsers.Where(x => x.Users != null))
                    {
                        if (!teamKeys.TryGetValue(qtu.TeamUid, out var teamKey)) continue;
                        if (teamKey == null) continue;

                        foreach (var userId in qtu.Users)
                        {
                            if (!userLookup.TryGetValue(userId, out var user)) continue;
                            if (!userKeys.TryGetValue(user.Username, out var pk)) continue;
                            if (pk == null) continue;

                            try
                            {
                                var publicKey = CryptoUtils.LoadPublicKey(pk);
                                var encTeamKey = CryptoUtils.EncryptRsa(teamKey, publicKey);
                                commands.Add(new TeamEnterpriseUserAddCommand
                                {
                                    TeamUid = qtu.TeamUid,
                                    EnterpriseUserId = userId,
                                    UserType = 0,
                                    TeamKey = encTeamKey.Base64UrlEncode()
                                });
                            }
                            catch
                            {
                                // ignore
                            }
                        }
                    }

                    if (commands.Any())
                    {
                        var rs = await auth.ExecuteCommands(commands);
                        if (rs.Any())
                        {
                            var l = rs.Last();
                            if (!l.IsSuccess)
                            {
                                log.LogInformation($"Add user to team error: {l.resultCode}");
                            }
                        }
                    }
                }
            }
        }

        public static async Task ExecuteDeviceApprove(IAuthentication auth, IList<string> messages)
        {
            var keysRq = new EnterpriseDataCommand
            {
                include = new[] {"devices_request_for_admin_approval"}
            };
            var rs = await auth.ExecuteAuthCommand<EnterpriseDataCommand, EnterpriseDataResponse>(keysRq);
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
                if (key.KeyTypeId != 2) continue;
                try
                {
                    var userDataKey = CryptoUtils.DecryptEc(key.UserEncryptedDataKey.ToByteArray(), _enterprisePrivateKey);
                    userDataKeys[key.EnterpriseUserId] = userDataKey;
                }
                catch (Exception e)
                {
                    messages.Add($"Data key decrypt error: {e.Message}");
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
                var message = $"Approve device for {deviceRs.EnterpriseUserId} {(deviceRs.Failed ? "failed" : "succeeded")}";
                Debug.WriteLine(message);
                messages.Add(message);
            }
        }

        public static async Task<Auth> ConnectToKeeper(ILogger log)
        {
            if (!await Semaphore.WaitAsync(TimeSpan.FromSeconds(10))) throw new Exception("Timed out");
            try
            {
                var configPath = GetKeeperConfigurationFilePath();
                var jsonCache = new JsonConfigurationCache(new JsonConfigurationFileLoader(configPath));
                var jsonConfiguration = new JsonConfigurationStorage(jsonCache);
                var auth = new Auth(new AuthUiNoAction(), jsonConfiguration)
                {
                    ResumeSession = true
                };
                await auth.Login(jsonConfiguration.LastLogin);
                jsonCache.Flush();

                var keysRq = new EnterpriseDataCommand
                {
                    include = new[] {"keys"}
                };
                var rs = await auth.ExecuteAuthCommand<EnterpriseDataCommand, EnterpriseDataResponse>(keysRq);
                if (string.IsNullOrEmpty(rs.Keys?.EccEncryptedPrivateKey))
                {
                    throw new Exception("Enterprise does not have EC key pair");
                }

                var encTreeKey = rs.TreeKey.Base64UrlDecode();
                var treeKey = rs.KeyTypeId switch
                {
                    1 => CryptoUtils.DecryptAesV1(encTreeKey, auth.AuthContext.DataKey),
                    2 => CryptoUtils.DecryptRsa(encTreeKey, auth.AuthContext.PrivateKey),
                    _ => throw new Exception("cannot decrypt tree key")
                };

                var privateKeyData = CryptoUtils.DecryptAesV2(rs.Keys.EccEncryptedPrivateKey.Base64UrlDecode(), treeKey);
                _enterprisePrivateKey = CryptoUtils.LoadPrivateEcKey(privateKeyData);
                return auth;
            }
            finally
            {
                Semaphore.Release();
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
