using System;
using System.Diagnostics.Eventing.Reader;
using System.Xml;
using System.Security;
using System.Collections;
namespace SharpGetUserLoginIPRPC
{
    class Program
    {
        //定义公共变量
        //static String queryPath;
        static EventLogSession session;

        static Hashtable logtypename = new Hashtable(){
            {2, "type = 2|Interactive|交互式登录"},
        {3, "type = 3|Network|网络登录"},
        {4, "type = 4|Batch|批处理登录 "},
        {5, "type = 5|Service|服务登录"},
        {7, "type = 7|Unlock|解锁登录"},
        {8, "type = 8|NetworkCleartext|网络明文方式登录 "},
        {10, "type = 10|Remotelnteractive|远程桌面方式登录"},
        {11, "type = 11|CachedUnlock|缓存域证书登录"},
        
    };



        // 获取本地
        public static EventLogSession getlocal()
        {
            Console.WriteLine("[*] Try to query local eventlog");

            session = new EventLogSession();

            return session;


        }

        public static EventLogSession getdomain(string arg)
        {
            Console.WriteLine("[*] Try to query remote eventlog");
            int pos1 = arg.IndexOf("\\");
            String domain = arg.Substring(0, pos1);
            int pos2 = arg.IndexOf(":");
            String username = arg.Substring(pos1 + 1, pos2 - pos1 - 1);
            int pos3 = arg.LastIndexOf("@");
            String password = arg.Substring(pos2 + 1, pos3 - pos2 - 1);
            String server = arg.Substring(pos3 + 1);
            SecureString securePwd = new SecureString();
            foreach (char c in password)
            {
                securePwd.AppendChar(c);
            }
            session = new EventLogSession(server, domain, username, securePwd, SessionAuthentication.Negotiate);

            return session;

        }

        public static EventLogSession workstation(string arg)
        {
            Console.WriteLine("[*] Try to query remote eventlog");
            int firstIndex = arg.IndexOf(':'); // 13
            string username = arg.Substring(0, firstIndex);
            int lastIndex = arg.LastIndexOf('@'); //26
            string password = arg.Substring(firstIndex + 1, lastIndex - firstIndex - 1);
            string server = arg.Substring(lastIndex + 1);
            SecureString securePwd = new SecureString();
            foreach (char c in password)
            {
                securePwd.AppendChar(c);
            }
            session = new EventLogSession(server, null, username, securePwd, SessionAuthentication.Negotiate);

            return session;

        }


        public static EventLogSession pth(string arg)
        {
            Console.WriteLine("[*] Try to query remote eventlog");
            string server = arg;

            session = new EventLogSession(server, null, null, null, SessionAuthentication.Negotiate);

            return session;

        }
        static void ShowUsage()
        {
            String Usage = @"
SharpGetUserLoginIPRPC
Use RPC to get the login IP of domain users through the event log.
Support local and remote access
Complie:
      C:\Windows\Microsoft.NET\Framework64\v3.5\csc.exe SharpGetUserLoginIPRPC.cs
      or
      C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe SharpGetUserLoginIPRPC.cs
Usage:
      SharpGetUserLoginIPRPC <target> <options>
target:
- localhost
- domain\username:password@server
- username:password@server

Eg:
      SharpGetUserLoginIPRPC.exe localhost # 本地
      SharpGetUserLoginIPRPC.exe admin:password@192.168.0.3 # 工作组环境
      SharpGetUserLoginIPRPC.exe domain.com\admin:password@192.168.0.3 # 域环境
      SharpGetUserLoginIPRPC.exe dc01.wolvez.com # 使用mimikatz pth 过后执行
      SharpGetUserLoginIPRPC.exe administrator:password@123@192.168.0.3  -month 1 # 筛选一个月
      SharpGetUserLoginIPRPC.exe administrator:password@123@192.168.0.3  -day 1 # 筛选一天
      SharpGetUserLoginIPRPC.exe administrator:password@123@192.168.0.3  -week 1 # 筛选一星期
      SharpGetUserLoginIPRPC.exe administrator:password@123@192.168.0.3  -hour 1 # 筛选一个小时
      SharpGetUserLoginIPRPC.exe administrator:password@123@192.168.0.3  -qu ssoadmin  # 筛选登录用户
      SharpGetUserLoginIPRPC.exe administrator:password@123@192.168.0.3  -qh 192.168.0.1  # 筛选访问ip或主机名
  
";
            Console.WriteLine(Usage);
            System.Environment.Exit(0);
        }


        static void Main(string[] args)
        {
            if (args.Length <= 0)
            {
                ShowUsage();

            }
            //三种情况：
            /*
             logviews.exe localhost //本地
             logviews.exe admin:password@192.168.0.3 //工作组环境
             logviews.exe domain.com\admin:password@192.168.0.3 //域环境
             logviews.exe dc01.wolvez.com //已经认证过 如 ipc 或pth
             logviews.exe 192.168.0.1   //已经认证过 如 ipc 或pth
             //以下为pth操作：
             mimikatz.exe  "privilege::debug" "sekurlsa::pth /user:administrator /domain:workstation /ntlm:1042e6c84109ee3b73a6a3fedba601b3" "exit"
             
             */
            try
            {

                string queryPath = "(Event/System/EventID=4624)";

                if (args[0] == "localhost" || args[0] == "127.0.0.1")
                {
                    session = getlocal();
                 
                }
                else if (args[0].Contains("@") && args[0].Contains("\\") && args[0].Contains(":"))
                {
                    session = getdomain(args[0]);
            

                }
                else if (args[0].Contains("@") && args[0].Contains(":"))
                {

                    session = workstation(args[0]);

                }
                else
                {
                    session = pth(args[0]);

                }

                foreach (string arg in args)
                {
                    //根据用户筛选
                    if (args.Length >= 2 && arg.Contains("-qu"))
                    {

                        int num = args.Length - 1;
                        string s = String.Format("*[EventData[Data[@Name='SubjectUserName'] and (Data='{0}')]]", args[num]);
                        queryPath += " and " + s;
                        
                    }

                    //根据ip地址或主机名筛选
                    else if (args.Length >= 2 && arg.Contains("-qh"))
                    {

                        int num = args.Length - 1;
                        string s = String.Format("*[EventData[Data[@Name='IpAddress'] and (Data='{0}')]]", args[num]);
                        queryPath += " and " + s;
                        
                        //Console.WriteLine(args[num]);
                    }
                    //按照小时筛选
                    else if (args.Length > 2 && arg.Contains("-hour"))
                    {

                        int num = args.Length - 1;
                        int hour = int.Parse(args[num]) * 3600000;
                        string s = String.Format("*[System[TimeCreated[timediff(@SystemTime) <= {0}]]]", hour);
                        queryPath += " and " + s;
                        
                    }
                    //按天筛选
                    else if (args.Length > 2 && arg.Contains("-day"))
                    {

                        int num = args.Length - 1;
                        int hour = int.Parse(args[num]) * 3600000 * 24;
                        string s = String.Format("*[System[TimeCreated[timediff(@SystemTime) <= {0}]]]", hour);
                        queryPath += " and " + s;
                        
                    }
                    //按星期筛选
                    else if (args.Length > 2 && arg.Contains("-week"))
                    {

                        int num = args.Length - 1;
                        int hour = int.Parse(args[num]) * 3600000 * 24 * 7;
                        string s = String.Format("*[System[TimeCreated[timediff(@SystemTime) <= {0}]]]", hour);
                        queryPath += " and " + s;
                        
                    }
                    //按月筛选
                    else if (args.Length > 2 && arg.Contains("-month"))
                    {

                        int num = args.Length - 1;
                        Int64 hour = int.Parse(args[num]) * 2629800000;
                        string s = String.Format("*[System[TimeCreated[timediff(@SystemTime) <= {0}]]]", hour);
                        queryPath += " and " + s;
                        
                    }
                    
                   


                }
                Console.WriteLine("[+] Query >" + queryPath);


                EventLogQuery eventLogQuery = new EventLogQuery("Security", PathType.LogName, queryPath)
                {
                    Session = session,
                    TolerateQueryErrors = true,
                    ReverseDirection = true
                };
                int flagTotal = 0;
                int flagExist = 0;
                using (EventLogReader eventLogReader = new EventLogReader(eventLogQuery))
                {
                    eventLogReader.Seek(System.IO.SeekOrigin.Begin, 0);
                    do
                    {
                        EventRecord eventData = eventLogReader.ReadEvent();
                        if (eventData == null)
                            break;
                        flagTotal++;
                        XmlDocument xmldoc = new XmlDocument();
                        xmldoc.LoadXml(eventData.ToXml());
                        XmlNodeList recordid = xmldoc.GetElementsByTagName("EventRecordID");
                        XmlNodeList data = xmldoc.GetElementsByTagName("Data");
                        String targetUserSid = data[4].InnerText;
                        String targetDomainName = data[6].InnerText;
                        String targetUserName = data[5].InnerText;
                        int Logtype = Convert.ToInt16(data[8].InnerText);

                        //String typename = logtypename[Logtype];
                        String ipAddress = data[18].InnerText;
                        if (targetUserSid.Length > 9 && ipAddress.Length > 8)
                        {
                            Console.WriteLine("[+] EventRecordID: " + recordid[0].InnerText);
                            Console.WriteLine("    TimeCreated  : " + eventData.TimeCreated);
                            Console.WriteLine("    Logtype:       " + logtypename[Logtype]);
                            Console.WriteLine("    DomainName:    " + targetDomainName);
                            Console.WriteLine("    UserName:      " + targetUserName);
                            Console.WriteLine("    IpAddress:     " + ipAddress);
                            flagExist++;
                        }
                        eventData.Dispose();
                    } while (true);
                    Console.WriteLine("Total: " + flagTotal + ", Exist: " + flagExist);
                }


            }
            catch (Exception e)
            {
                Console.WriteLine("[!] ERROR: {0}", e);
            }
        }

    }
}
