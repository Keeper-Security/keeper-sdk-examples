//  _  __
// | |/ /___ ___ _ __  ___ _ _ ®
// | ' </ -_) -_) '_ \/ -_) '_|
// |_|\_\___\___| .__/\___|_|
//              |_|
//
// Keeper SDK
// Copyright 2021 Keeper Security Inc.
// Contact: ops@keepersecurity.com
//

using System;
using System.Linq;
using System.Threading.Tasks;
using KeeperSecurity.Authentication;
using KeeperSecurity.Authentication.Async;
using KeeperSecurity.Configuration;
using KeeperSecurity.Enterprise;
using KeeperSecurity.Utils;

namespace Sample
{
    internal static class Program
    {
        private static readonly InputManager InputManager = new InputManager();

        public static InputManager GetInputManager()
        {
            return InputManager;
        }

        const string Prompt = @"
1. List Nodes
2. List Users
3. List Roles
4. Create Node
5. Toggle Node Isolation
6. Assign User to Role
Q. Quit
";

        private static async Task MainLoop()
        {
            // Keeper SDK needs a storage to save configuration
            // such as: last login name, device token, etc
            var configuration = new JsonConfigurationStorage("config.json");
            var email = configuration.LastLogin;

            if (string.IsNullOrEmpty(configuration.LastLogin))
            {
                email = await GetInputManager().ReadLine();
            }
            if (string.IsNullOrEmpty(configuration.LastLogin))
            {
                return;
            }

            Console.WriteLine($"Connecting to Keeper as {email}");
            using var auth = new Auth(new ConsoleAuthUi(GetInputManager()), configuration)
            {
                Endpoint = { DeviceName = "LPL Sanple" }
            };
            auth.Endpoint.Server = "dev.keepersecurity.com";

            await auth.Login(email);
            if (!auth.IsAuthenticated())
            {
                return;
            }
            if (!auth.AuthContext.IsEnterpriseAdmin)
            {
                Console.WriteLine("Not an enterprise admiin.");
                return;
            }

            var enterpriseData = new EnterpriseData();
            var roleData = new RoleDataManagement();
            var enterpriseLoader = new EnterpriseLoader(auth, new EnterpriseDataPlugin[] { enterpriseData, roleData });

            await enterpriseLoader.Load();

            while (true)
            {
                Console.WriteLine(Prompt);
                Console.Write($"{enterpriseLoader.EnterpriseName} > ");
                var answer = await GetInputManager().ReadLine();
                if (int.TryParse(answer, out var choice))
                {
                    switch (choice)
                    {
                        case 1:
                            {
                                var table = new Tabulate(4);
                                table.AddHeader("Node ID", "Node Name", "Parent Id", "Isolated Node");
                                foreach (var node in enterpriseData.Nodes)
                                {
                                    table.AddRow(node.Id, node.DisplayName, node.ParentNodeId > 0 ? node.ParentNodeId.ToString() : "", node.RestrictVisibility ? "Isolated" : "");
                                }
                                table.Dump();
                            }

                            break;
                        case 2:
                            {
                                var table = new Tabulate(5);
                                table.AddHeader("User ID", "User Email", "User Name", "Node ID", "Status");
                                foreach (var user in enterpriseData.Users)
                                {
                                    table.AddRow(user.Id, user.Email, user.DisplayName, user.ParentNodeId, user.UserStatus);
                                }
                                table.Dump();
                            }

                            break;

                        case 3:
                            {
                                var table = new Tabulate(5);
                                table.AddHeader("Role ID", "Role Name", "Node ID", "Cascade?", "Users in Role");
                                foreach (var role in roleData.Roles)
                                {
                                    var cnt = roleData.GetUsersForRole(role.Id).Count();
                                    table.AddRow(role.Id, role.DisplayName, role.ParentNodeId, role.VisibleBelow, cnt);
                                }
                                table.Dump();
                            }

                            break;

                        case 4:
                            {
                                Console.Write("\nNode Name: ");
                                var nodeName = await GetInputManager().ReadLine();
                                if (!string.IsNullOrEmpty(nodeName))
                                {
                                    Console.Write("Parent Node ID (empty for Root Node): ");
                                    EnterpriseNode parentNode = null;
                                    var parent = await GetInputManager().ReadLine();
                                    if (!string.IsNullOrEmpty(parent))
                                    {
                                        if (long.TryParse(parent, out var n))
                                        {
                                            var node = enterpriseData.Nodes.FirstOrDefault(x => x.Id == n);
                                            if (node == null)
                                            {
                                                Console.WriteLine($"Parent node ID \"{parent}\" not found.");
                                            }
                                        }
                                    }
                                    else
                                    {
                                        parentNode = enterpriseData.RootNode;
                                    }

                                    if (parentNode != null)
                                    {
                                        try
                                        {
                                            var n = await enterpriseData.CreateNode(nodeName, parentNode);
                                            Console.WriteLine($"Node created. Node ID = {n.Id}");
                                            await enterpriseLoader.Load();
                                        }
                                        catch (Exception e)
                                        {
                                            Console.WriteLine(e.Message);
                                        }
                                    }
                                }
                            }
                            break;

                        case 5:
                            {
                                Console.Write("Enter Node ID to toggle Node Isolation: ");
                                EnterpriseNode node = null;
                                answer = await GetInputManager().ReadLine();
                                if (!string.IsNullOrEmpty(answer))
                                {
                                    if (long.TryParse(answer, out var n))
                                    {
                                        var nd = enterpriseData.Nodes.FirstOrDefault(x => x.Id == n);
                                        if (nd == null)
                                        {
                                            Console.WriteLine($"Parent node ID \"{answer}\" not found.");
                                        }
                                        else if (ReferenceEquals(nd, enterpriseData.RootNode)) 
                                        {
                                            Console.WriteLine($"Cannot change Node Isolation on the Root node.");
                                        }
                                        else 
                                        {
                                            node = nd;
                                        }
                                    }
                                }
                                if (node != null) 
                                {
                                    try
                                    {
                                        await enterpriseData.SetRestrictVisibility(node.Id);
                                        Console.WriteLine($"Node isolation id toggled on Node ID: {node.Id}");
                                        await enterpriseLoader.Load();
                                    }
                                    catch (Exception e)
                                    {
                                        Console.WriteLine(e.Message);
                                    }

                                }

                            }
                            break;

                        case 6:
                            {
                                EnterpriseRole role = null;
                                Console.Write("Enter Role ID or Role Node: ");
                                answer = await GetInputManager().ReadLine();
                                if (!string.IsNullOrEmpty(answer))
                                {
                                    if (long.TryParse(answer, out var n))
                                    {
                                        roleData.TryGetRole(n, out role);
                                    }
                                    if (role == null)
                                    {
                                        role = roleData.Roles.FirstOrDefault(x => string.Equals(x.DisplayName, answer, StringComparison.CurrentCultureIgnoreCase));
                                    }
                                    if (role == null)
                                    {
                                        Console.WriteLine($"Role \"{answer}\" not found.");
                                        return;
                                    }
                                }
                                else
                                {
                                    return;
                                }
                                Console.WriteLine($"Current role:\nRole ID: {role.Id}\nRole Name: {role.DisplayName}");

                                EnterpriseUser user = null;
                                Console.Write("Enter User ID or User Email: ");
                                answer = await GetInputManager().ReadLine();
                                if (!string.IsNullOrEmpty(answer))
                                {
                                    if (long.TryParse(answer, out var n))
                                    {
                                        enterpriseData.TryGetUserById(n, out user);
                                    }
                                    if (user == null)
                                    {
                                        enterpriseData.TryGetUserByEmail(answer, out user);
                                    }
                                    if (user == null)
                                    {
                                        Console.WriteLine($"User \"{answer}\" not found.");
                                        return;
                                    }
                                }
                                else
                                {
                                    return;
                                }
                                Console.WriteLine($"\nUser ID: {user.Id}\nEmail: {user.Email}");

                                await roleData.AddUserToRole(role.Id, user.Id);

                                Console.WriteLine($"User \"{user.Email}\" added to role \"{role.DisplayName}\"");
                            }
                            break;
                    }
                }
                else
                {
                    if (string.Equals(answer, "q", StringComparison.InvariantCultureIgnoreCase))
                    {
                        break;
                    }
                    Console.WriteLine($"Invalid choice: {answer}");
                }
            }
        }

        private static void Main()
        {
            Console.CancelKeyPress += (s, e) => { Environment.Exit(-1); };

            _ = Task.Run(async () =>
            {
                try
                {
                    await MainLoop();
                }
                catch (Exception e)
                {
                    Console.WriteLine(e.Message);
                }

                Environment.Exit(0);
            });

            InputManager.Run();
        }

    }

}