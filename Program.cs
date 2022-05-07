using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.DirectoryServices.ActiveDirectory;

namespace Detect_Password_Spraying
{
    internal class Program
    {
        static List<SavedUserAttributesTimeGroup> lstSavedUserAttributesTimeGroup = new List<SavedUserAttributesTimeGroup>();

        static void Main()
        {
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Blue;
            Console.WriteLine("██████╗ ███████╗████████╗███████╗ ██████╗████████╗   ███████╗██████╗ ██████╗  █████╗ ██╗   ██╗");
            Console.WriteLine("██╔══██╗██╔════╝╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝   ██╔════╝██╔══██╗██╔══██╗██╔══██╗╚██╗ ██╔╝");
            Console.WriteLine("██║  ██║█████╗     ██║   █████╗  ██║        ██║█████╗███████╗██████╔╝██████╔╝███████║ ╚████╔╝ ");
            Console.WriteLine("██║  ██║██╔══╝     ██║   ██╔══╝  ██║        ██║╚════╝╚════██║██╔═══╝ ██╔══██╗██╔══██║  ╚██╔╝  ");
            Console.WriteLine("██████╔╝███████╗   ██║   ███████╗╚██████╗   ██║      ███████║██║     ██║  ██║██║  ██║   ██║   ");
            Console.WriteLine("╚═════╝ ╚══════╝   ╚═╝   ╚══════╝ ╚═════╝   ╚═╝      ╚══════╝╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   ");
            Console.WriteLine("                                                                          by @ScarredMonk");
            Console.ForegroundColor = ConsoleColor.Gray;
            try
            {
                Domain.GetCurrentDomain().ToString();
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine(ex.Message + "\n\nPlease run it inside the domain joined machine \n\n");
                Console.ForegroundColor = ConsoleColor.Gray;
                return;
            }

            DirectoryEntry adObject = new DirectoryEntry();
            DirectorySearcher searcher = new DirectorySearcher(adObject)
            {
                SearchScope = SearchScope.Subtree,
                Filter = "(&(objectclass=user)(!(objectclass=computer))(!(badPwdCount=0)))"
            };
            var queryattributes = searcher.FindAll();
            CheckPassSpray(true);

            while (true)
            {
                CheckPassSpray();
                Thread.Sleep(3000);
            }

        }

        private static void CheckPassSpray(bool isSave=false)
        {
            List<UserAttributes> lstUserAttributes = new List<UserAttributes>();
            DirectoryEntry adFolderObject = new DirectoryEntry();
            DirectorySearcher searcher = new DirectorySearcher(adFolderObject)
            {
                SearchScope = SearchScope.Subtree,
                Filter = "(&(objectclass=user)(!(objectclass=computer))(!(badPwdCount=0)))"
            }; 
            var queryattributes = searcher.FindAll();
            if (isSave)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("\n [+] Existing Domain Accounts having failed login attempts \n");
                Console.ForegroundColor = ConsoleColor.Gray;
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine(" ------------------------------------------------------------------");
                Console.WriteLine("|    Username    | badPwdCount |   Bad Password Attempt TimeStamp  |");
                Console.WriteLine(" ----------------|-------------|-----------------------------------");
                Console.ForegroundColor = ConsoleColor.Gray;
            }

            foreach (SearchResult adObject in queryattributes)
            {
                UserAttributes userAttributes = new UserAttributes()
                {
                    Name = adObject.Properties["CN"][0].ToString(),
                    badPasswordTime = Convert.ToInt64(adObject.Properties["badPasswordTime"][0]),
                    badPwdCount = Convert.ToInt32(adObject.Properties["badPwdCount"][0])
                };
                lstUserAttributes.Add(userAttributes);
                if (isSave)
                {
                    Console.WriteLine(String.Format("|{0,16}|{1,13}|{2,35}|", userAttributes.Name, userAttributes.badPwdCount, userAttributes.badPasswordDateTime));
                }
            }

            var groupedValues = lstUserAttributes.GroupBy(g => g.badPasswordDateTime).Select(g => new SavedUserAttributesTimeGroup() { badPasswordDateTime = g.Key, listSavedUserAttributesListCount = g.ToList() });

            if (isSave)
            {
                lstSavedUserAttributesTimeGroup.AddRange(groupedValues);
            }
            else
            {
                foreach (var item in groupedValues)
                {
                    if (lstSavedUserAttributesTimeGroup.Any(x => x.badPasswordDateTime == item.badPasswordDateTime))
                    {
                        //Will add advanced scenarios here
                    }
                    else
                    {
                        lstSavedUserAttributesTimeGroup.Add(item);
                        if (item.listSavedUserAttributesListCount.Count > 1) 
                        {
                            Console.ForegroundColor = ConsoleColor.Green;
                            Console.WriteLine("\n [!] PASSWORD SPRAYING HAS BEEN DETECTED !! \n");
                            Console.ForegroundColor = ConsoleColor.Gray;
                            Console.WriteLine($"\n [+] Failed login attempts at {item.badPasswordDateTime} for {item.listSavedUserAttributesListCount.Count} users, \n");
                            Console.ForegroundColor = ConsoleColor.DarkRed;
                            Console.WriteLine("[" +$"{string.Join(", ", item.listSavedUserAttributesListCount.Select(x => x.Name))}"+ "]\n");
                            Console.ForegroundColor = ConsoleColor.Gray;
                        } else
                        {
                            Console.ForegroundColor = ConsoleColor.Yellow;
                            Console.WriteLine("\n [...] Failed login attempt for a single user \n");
                            Console.ForegroundColor = ConsoleColor.Gray;
                        }
                    }
                }
            }
        }
    }
    public class UserAttributes
    {
        public string Name { get; set; }
        public long badPasswordTime { get; set; }
        public DateTimeOffset badPasswordDateTime {
            get {
                DateTime date = new DateTime(1601, 01, 01, 0, 0, 0, DateTimeKind.Utc).AddTicks(badPasswordTime);
                return new DateTime(date.Year, date.Month, date.Day, date.Hour, date.Minute, date.Second, date.Kind);
            }
        }
        public int badPwdCount { get; set; }
    }

    public class SavedUserAttributesTimeGroup
    {
        public DateTimeOffset badPasswordDateTime { get; set; }
        public List<UserAttributes> listSavedUserAttributesListCount { get; set; }
    }
}