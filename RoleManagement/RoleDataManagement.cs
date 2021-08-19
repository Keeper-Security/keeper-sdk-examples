using KeeperSecurity.Commands;
using KeeperSecurity.Authentication;
using System.Threading.Tasks;
using KeeperSecurity.Utils;
using System.Collections.Generic;
using Enterprise;
using System;
using System.Diagnostics;
using Google.Protobuf;
using KeeperSecurity.Enterprise;
using System.Runtime.Serialization;
using System.Text;

namespace Sample
{
    public interface IRoleDataManagement : IRoleData
    {
        Task<EnterpriseRole> CreateRole(string roleName, long nodeId, bool visibleBelow, bool newUserInherit);
        Task DeleteRole(long roleId);

        Task AddUserToRole(long roleId, long userId);
        Task AddUserToAdminRole(long roleId, long userId, byte[] userRsaPublicKey);
        Task RemoveUserFromRole(long roleId, long userId);
        Task AddTeamToRole(long roleId, string teamUid);
        Task RemoveTeamFromRole(long roleId, string teamUid);
        Task AddRoleEnforcement(long roleId, string name, object value);
        Task DeleteRoleEnforcement(long roleId, string name);
        Task CopyRole(long roleId, long nodeId, Action<string> errors);
    }

    public class RoleDataManagement : RoleData, IRoleDataManagement
    {
        private Dictionary<long, byte[]> _adminRoleKeys = new Dictionary<long, byte[]>();

        private async Task<byte[]> GetRoleKey(long roleId)
        {
            lock (_adminRoleKeys)
            {
                if (_adminRoleKeys.TryGetValue(roleId, out var result))
                {
                    return result;
                }
            }

            var krq = new GetEnterpriseDataKeysRequest();
            krq.RoleId.Add(roleId);
            var krs = await Enterprise.Auth.ExecuteAuthRest<GetEnterpriseDataKeysRequest, GetEnterpriseDataKeysResponse>("enterprise/get_enterprise_data_keys", krq);
            foreach (var rKey in krs.ReEncryptedRoleKey)
            {
                if (rKey.RoleId == roleId)
                {
                    try
                    {
                        var roleKey = CryptoUtils.DecryptAesV2(rKey.EncryptedRoleKey.ToByteArray(), Enterprise.TreeKey);
                        lock (_adminRoleKeys)
                        {
                            if (!_adminRoleKeys.ContainsKey(roleId))
                            {
                                _adminRoleKeys.Add(roleId, roleKey);
                            }
                            return roleKey;
                        }
                    }
                    catch (Exception e)
                    {
                        Debug.WriteLine(e.Message);
                    }
                }
            }

            foreach (var rKey in krs.RoleKey)
            {
                if (rKey.RoleId == roleId)
                {
                    byte[] roleKey = null;
                    try
                    {
                        switch (rKey.KeyType)
                        {
                            case EncryptedKeyType.KtEncryptedByDataKey:
                                roleKey = CryptoUtils.DecryptAesV1(rKey.EncryptedKey.Base64UrlDecode(), Enterprise.Auth.AuthContext.DataKey);
                                break;
                            case EncryptedKeyType.KtEncryptedByPublicKey:
                                roleKey = CryptoUtils.DecryptRsa(rKey.EncryptedKey.Base64UrlDecode(), Enterprise.Auth.AuthContext.PrivateKey);
                                break;
                        }
                    }
                    catch (Exception e)
                    {
                        Debug.WriteLine(e.Message);
                    }

                    if (roleKey != null)
                    {
                        lock (_adminRoleKeys)
                        {
                            if (!_adminRoleKeys.ContainsKey(roleId))
                            {
                                _adminRoleKeys.Add(roleId, roleKey);
                            }
                            return roleKey;
                        }
                    }
                }
            }

            return null;
        }

        public async Task<EnterpriseRole> CreateRole(string roleName, long nodeId, bool visibleBelow, bool newUserInherit)
        {
            var encryptedData = new EncryptedData
            {
                DisplayName = roleName
            };

            var roleId = await Enterprise.GetEnterpriseId();
            var rq = new RoleAddCommand
            {
                RoleId = roleId,
                NodeId = nodeId,
                EncryptedData = EnterpriseUtils.EncryptEncryptedData(encryptedData, Enterprise.TreeKey),
                VisibleBelow = visibleBelow,
                NewUserInherit = newUserInherit
            };

            await Enterprise.Auth.ExecuteAuthCommand(rq);
            await Enterprise.Load();
            return TryGetRole(roleId, out var role) ? role : null;
        }

        public async Task DeleteRole(long roleId)
        {
            await Enterprise.Auth.ExecuteAuthCommand(new RoleDeleteCommand { RoleId = roleId }); ;
            await Enterprise.Load();
        }

        public async Task AddUserToRole(long roleId, long userId)
        {
            var rq = new RoleUserAddCommand
            {
                RoleId = roleId,
                EnterpriseUserId = userId,
            };

            await Enterprise.Auth.ExecuteAuthCommand(rq);
            await Enterprise.Load();
        }

        public async Task AddUserToAdminRole(long roleId, long userId, byte[] userRsaPublicKey)
        {
            var publicKey = CryptoUtils.LoadPublicKey(userRsaPublicKey);
            var rq = new RoleUserAddCommand
            {
                RoleId = roleId,
                EnterpriseUserId = userId,
                TreeKey = CryptoUtils.EncryptRsa(Enterprise.TreeKey, publicKey).Base64UrlEncode(),
            };
            var roleKey = await GetRoleKey(roleId);
            if (roleKey != null)
            {
                rq.RoleAdminKey = CryptoUtils.EncryptRsa(roleKey, publicKey).Base64UrlEncode();
            }
            await Enterprise.Auth.ExecuteAuthCommand(rq);
            await Enterprise.Load();
        }

        public async Task RemoveUserFromRole(long roleId, long userId)
        {
            var rq = new RoleUserRemoveCommand
            {
                RoleId = roleId,
                EnterpriseUserId = userId,
            };

            await Enterprise.Auth.ExecuteAuthCommand(rq);
            await Enterprise.Load();
        }

        public async Task AddTeamToRole(long roleId, string teamUid)
        {
            var rq = new RoleTeams();
            rq.RoleTeam.Add(new RoleTeam
            {
                RoleId = roleId,
                TeamUid = ByteString.CopyFrom(teamUid.Base64UrlDecode()),
            });

            await Enterprise.Auth.ExecuteAuthRest("enterprise/role_team_add", rq);
            await Enterprise.Load();
        }

        public async Task RemoveTeamFromRole(long roleId, string teamUid)
        {
            var rq = new RoleTeams();
            rq.RoleTeam.Add(new RoleTeam
            {
                RoleId = roleId,
                TeamUid = ByteString.CopyFrom(teamUid.Base64UrlDecode()),
            });

            await Enterprise.Auth.ExecuteAuthRest("enterprise/role_team_remove", rq);
            await Enterprise.Load();
        }


        public async Task AddRoleEnforcement(long roleId, string name, object value)
        {
            AuthenticatedCommand rq;
            switch (value)
            {
                case Dictionary<string, object> dict:
                    rq = new RoleEnforcementAddJsonCommand
                    {
                        RoleId = roleId,
                        Enforcement = name,
                        Value = dict
                    };
                    break;

                case bool b:
                    if (b)
                    {
                        rq = new RoleEnforcementAddBoolCommand
                        {
                            RoleId = roleId,
                            Enforcement = name,
                        };
                    }
                    else
                    {
                        await DeleteRoleEnforcement(roleId, name);
                        return;
                    }
                    break;

                default:
                    rq = new RoleEnforcementAddCommand
                    {
                        RoleId = roleId,
                        Enforcement = name,
                        Value = value.ToString()
                    };
                    break;
            }

            await Enterprise.Auth.ExecuteAuthCommand(rq);
        }

        public async Task DeleteRoleEnforcement(long roleId, string name)
        {
            var rq = new RoleEnforcementRemoveCommand
            {
                RoleId = roleId,
                Enforcement = name,
            };
            await Enterprise.Auth.ExecuteAuthCommand(rq);
        }


        public async Task CopyRole(long roleId, long nodeId, Action<string> errors)
        {
            if (!TryGetRole(roleId, out var role))
            {
                throw new Exception($"Role ID {roleId} not found.");
            }

            if (role.Id == nodeId)
            {
                throw new Exception($"Role ID {roleId} already belongs to Node ID {nodeId}.");
            }

            var newRole = await CreateRole(role.DisplayName, nodeId, role.VisibleBelow, role.NewUserInherit);
            var enforcements = GetEnforcementsForRole(roleId);
            foreach (var enforcement in enforcements)
            {
                try
                {
                    object objectValue = null;
                    if (enforcement.Value == "true" || enforcement.Value == "false")
                    {
                        objectValue = enforcement.Value == "true";
                    }
                    else if (enforcement.Value.Length >= 2 && enforcement.Value[0] == '{' && enforcement.Value[enforcement.Value.Length - 1] == '}')
                    {
                        objectValue = JsonUtils.ParseJson<Dictionary<string, object>>(Encoding.UTF8.GetBytes(enforcement.Value));
                    }
                    else
                    {
                        objectValue = enforcement.Value;
                    }
                    await AddRoleEnforcement(newRole.Id, enforcement.EnforcementType, objectValue);
                }
                catch (Exception e)
                {
                    errors?.Invoke($"{enforcement.EnforcementType}: {e.Message}");
                }
            }
        }
    }

    [DataContract]
    public class RoleEnforcementAddJsonCommand : RoleEnforcementCommand
    {
        public RoleEnforcementAddJsonCommand() : base("role_enforcement_add")
        {
        }

        [DataMember(Name = "value")]
        public Dictionary<string, object> Value { get; set; }
    }

    [DataContract]
    public class RoleEnforcementAddBoolCommand : RoleEnforcementCommand
    {
        public RoleEnforcementAddBoolCommand() : base("role_enforcement_add")
        {
        }
    }
}
