using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.Linq;
using System.Reflection;

namespace SignatureBuilder
{
    class Program
    {
        public static int currentLine = 0;
        static LogLevel ExitLevel = LogLevel.WARN | LogLevel.ERR;

        static void Main(string[] cmdArgs)
        {
            Version version = Assembly.GetExecutingAssembly().GetName().Version;
            AssemblyDescriptionAttribute releaseDate = (AssemblyDescriptionAttribute)Attribute.GetCustomAttribute(Assembly.GetExecutingAssembly(), typeof(AssemblyDescriptionAttribute));

            Console.WriteLine($"============== Signature Builder - For Parser rev5 ==============\r\n" +
                $"\t+ Build: {version} [{releaseDate.Description}]\r\n\r\n");

            var file = (cmdArgs.Length >= 1 ? cmdArgs[0] : ".") + "/parser.txt";
            var outFile = (cmdArgs.Length >= 2 ? cmdArgs[1] : ".") + "/_pkts.v5.ignore.json";
            if (!System.IO.File.Exists(file))
            {
                Log(LogLevel.ERR | LogLevel.EXIT, "File not found @ " + file);
            }
            string[] lines = System.IO.File.ReadAllLines(file);

            /*
             {
                 // layer 1
                 "6F": {
                    // layer 2
                    "name": "Hero Effect",
                    "signature": {
                        // layer 3
                        "$4 [REPS] $4 $1 $1 [REPE]": {
                            // layer 4
                            "desc": "",
                            "params": [ // array of dicts
                                { "name": "HeroID" }, // dict<string, dynamic>
                                { "name": "EffectID", "func": ["eHeroEffect", ] }
                            ]
                        }
                    }
                }
            }*/
            bool parserSectionStart = false;
            ParserCode obj = null;

            foreach (string tmp in lines)
            {
                ++currentLine;

                var line = tmp.Replace("/// ", "").Trim();
                if (line == "" || line.StartsWith("//"))
                    continue;

                // split the actual code, remove comment (//) part.
                if (line.Contains("//"))
                    line = line.Split("//")[0].Trim();

                if (line == "<parser>")
                {
                    // start of parser tag
                    parserSectionStart = true;
                    continue;
                }
                else if (line == "</parser>")
                {
                    // end of parser tag
                    parserSectionStart = false;
                    obj = null;
                    continue;
                }

                if (!parserSectionStart)
                {
                    // </parser> exists before but no start tag after that.
                    Log(LogLevel.ERR | LogLevel.EXIT,
                        "Unexpected line outside <parser> tag.",
                        "Raw: " + line
                    );
                }

                if (line.StartsWith("Fragment["))
                {
                    var m = ParserCode.regexFrag.Match(line).Groups;
                    if (m[1].Value == "")
                    {
                        Log(LogLevel.ERR | LogLevel.EXIT,
                            "Malform Fragment declaration found.",
                            "Captured: [" + string.Join(", ", m) + "]",
                            "Raw: " + line
                        );
                    }

                    var frag = new Fragment(m[1].Value);
                    if (!Fragment.FragmentPool.TryAdd(frag.Name, frag))
                    {
                        Log(LogLevel.ERR | LogLevel.EXIT,
                            "Failed to declare Fragment.",
                            "Fragment Name: " + frag.Name,
                            "Raw: " + line
                        );
                    }
                    Log(LogLevel.NOR, $"New Fragment[{frag.Name}]");
                    obj = frag;
                }
                else if (line.StartsWith("Packet["))
                {
                    // packet declaration
                    var m = ParserCode.regexPkt.Match(line).Groups;
                    if (m[1].Value == "" || m[2].Value == "")
                    {
                        Log(LogLevel.WARN,
                            $"Skipped mismatch Packet Declaration",
                            "Captured: {" + string.Join(", ", m) + "}",
                            "Raw: " + line
                        );
                        continue;
                    }

                    var pkt = new Packet(m[1].Value, m[2].Value.ToUpper());
                    if (!Packet.PacketPool.TryAdd(pkt.Header, pkt))
                        Log(LogLevel.ERR | LogLevel.EXIT, $"Duplicated Packet Header[{pkt.Header}]");

                    Log(LogLevel.NOR, $"New Packet[{pkt.Header.PadRight(4, ' ')}] Desc[{pkt.Desc}]");
                    obj = pkt;
                }
                else
                {
                    if (obj == null)
                    {
                        Log(LogLevel.ERR | LogLevel.EXIT,
                            "Unexpected line before Packet / Fragment declaration.",
                            "Raw: " + line
                        );
                    }

                    // push to obj's List for further parsing.
                    obj.AddLine(currentLine, line);
                }
            }

            Console.WriteLine("");

            // loop all objects to do parsing
            //Fragment.FragmentPool.Values.ToArray()[1].BuildSignature();
            JObject mainDict = new JObject();
            Fragment.FragmentPool.Values.ToList().ForEach(frag => frag.BuildSignature());
            Packet.PacketPool.Values.ToList().ForEach(pkt =>
            {
                pkt.BuildSignature();
                mainDict.Add(pkt.Header, new JObject() {
                    { "desc", pkt.Desc },
                    { "signature", pkt.Signatures }
                });
            });

            // add version & timestamp
            mainDict.Add("_timestamp", DateTimeOffset.UtcNow.ToUnixTimeSeconds() * 1000);
            mainDict.Add("_builder", new JArray() { releaseDate.Description.Split(" ")[0], "build " + version, "5" });

            System.IO.File.WriteAllText(outFile, JsonConvert.SerializeObject(mainDict));

            Console.WriteLine("");
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("[+] Build Success! Output File: " + outFile);
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("\nPress any key to exit.");
            Console.ReadKey();
        }

        public static void Log(LogLevel lv, params string[] msgs)
        {
            Log(lv, 0, msgs);
        }
        public static void Log(LogLevel lv, int indentLv, params string[] msgs)
        {
            Console.ForegroundColor = lv.GetColor();
            string indent = "";
            for (int i = 0; i < indentLv; i++)
                indent += "\t";

            Console.WriteLine($"{indent}[{lv.GetSymbol()}] {msgs[0]} [@Line:{currentLine}]");

            for (int i = 1; i < msgs.Length; i++)
                Console.WriteLine($"{indent}\t+ {msgs[i]}");

            if (msgs.Length > 1)
                Console.WriteLine($"");

            if (lv.HasFlag(LogLevel.EXIT) || lv.HasFlag(ExitLevel))
            {
                Console.ForegroundColor = ConsoleColor.White;
                Console.WriteLine("Press any key to exit.");
                Console.ReadKey();
                Environment.Exit(1);
            }
        }
    }

    public enum LogLevel
    {
        NOR = 1 << 0,
        WARN = 1 << 1,
        ERR = 1 << 2,
        DEBUG = 1 << 3,
        EXIT = 1 << 4,
    }

    public static class LogLevelMethods
    {
        public static string GetSymbol(this LogLevel lv)
        {
            switch (lv)
            {
                default:
                case LogLevel.NOR:
                    return "+";
                case LogLevel.WARN:
                    return "!";
                case LogLevel.ERR:
                    return "-";
                case LogLevel.DEBUG:
                    return "*";
            }
        }

        public static ConsoleColor GetColor(this LogLevel lv)
        {
            if (lv.HasFlag(LogLevel.WARN))
                return ConsoleColor.Yellow;
            if (lv.HasFlag(LogLevel.ERR))
                return ConsoleColor.Red;
            if (lv.HasFlag(LogLevel.DEBUG))
                return ConsoleColor.Blue;

            //return ConsoleColor.Green;
            return ConsoleColor.White;
        }
    }
}
