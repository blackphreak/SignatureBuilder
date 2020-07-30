using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Text;
using System.Text.RegularExpressions;

namespace SignatureBuilder
{
    public abstract class ParserCode
    {
        public static Regex regexFrag = new Regex(@"\+?\s?Fragment\[(\S+)\]", RegexOptions.Compiled | RegexOptions.Singleline);
        public static Regex regexPkt = new Regex(@"Packet\[(.+?)\]:(([0-9A-Fa-f]{2})+)", RegexOptions.Compiled | RegexOptions.Singleline);
        /// <summary>
        /// [1]: Desc, [3]: Actual Hex-Byte
        /// </summary>
        public static Regex regexSubcate = new Regex(@"SubCate\[(.+?)\](:([0-9A-Fa-f]{2})+)?", RegexOptions.Compiled | RegexOptions.Singleline);
        public static Regex regexSign = new Regex(@"(\$[124]|([A-Fa-f0-9]{2})+|64\$4|73\$4\$gbk|\$gbk|param){1}", RegexOptions.Compiled | RegexOptions.Singleline);

        /// <summary>
        /// original line number : sanitized code from that line
        /// </summary>
        protected Dictionary</*ori line num*/int, /*line code*/string> Lines = new Dictionary<int, string>();

        public void AddLine(int lineNum, string code)
        {
            if (!Lines.TryAdd(lineNum, code))
                Program.Log(LogLevel.ERR | LogLevel.EXIT, "Failed to add code line with same line number"); // this will never happen..
        }

        public abstract void BuildSignature();

        /// <summary>
        /// 
        /// </summary>
        /// <param name="obj"></param>
        /// <param name="line"></param>
        /// <returns>(Signature, JObject)</returns>
        public (string, JObject) ParseSignatureLine(string line)
        {
            dynamic paramInfo = new JObject();

            if (line.StartsWith("pad-"))
            {
                string retn = "";

                // build for padding bytes
                for (int i = 0; i < int.Parse(line[4..].Trim()); i++)
                    retn += "00";

                paramInfo.name = "Padding";

                return (retn, paramInfo);
            }

            if (!line.Contains(":") || line.StartsWith("SubCate["))
                return (null, null);

            // ignore comment "//" after argument signature
            var args = line.Split(":");

            paramInfo.name = args[0];

            // args[1] validation
            if (!regexSign.Match(args[1]).Success)
            {
                Program.Log(LogLevel.ERR | LogLevel.EXIT,
                    "Invalid Signature.",
                    "Args[1]: [" + args[1] + "]",
                    "Raw: " + line
                );
            }

            // parse special information
            string curr = "";
            for (int i = 2; i < args.Length; i++)
            {
                curr = args[i].Split("//")[0].TrimEnd();
                if (curr.StartsWith("R["))
                {
                    // Reference
                    // remove "R[" & "]":
                    var arr = new JArray();
                    paramInfo["func"] = arr;
                    foreach (var str in args[i][2..^1].Split(","))
                        arr.Add(str);

                    switch (arr[0].ToString().ToUpper())
                    {
                        case "SKILL":
                            arr[0] = "db_Skill";
                            break;
                        case "NPC":
                            paramInfo["func"][0] = "db_NPC";
                            break;
                        case "MAP":
                            paramInfo["func"][0] = "db_Map";
                            break;
                        case "FS":
                            paramInfo["func"][0] = "db_FormatString";
                            break;
                        case "ITEM":
                            paramInfo["func"][0] = "db_Item";
                            break;
                        default:
                            Program.Log(LogLevel.WARN,
                                @"Failed to parse ""R"" option",
                                "Unknown Reference Database: [" + arr[0] + "]",
                                "Raw: " + curr
                            );
                            continue;
                    }
                }
                else if (curr.StartsWith("Fn["))
                {
                    // Function
                    // remove "Fn[" & "]" before split:
                    paramInfo["func"] = new JArray(curr[3..^1].Split(","));
                }
                else if (curr.StartsWith("T"))
                {
                    // Force Data Type
                    var m = Regex.Match(curr, @"T\[(byte|short|ushort|int|uint)\].*", RegexOptions.Compiled).Groups;
                    if (m[1].Value == " ")
                    {
                        Program.Log(LogLevel.WARN,
                            @"Failed to parse ""T"" option",
                            "Captured: [" + string.Join(", ", m) + "]",
                            "Raw: " + curr
                        );
                        continue;
                    }
                    paramInfo["type"] = m[1].Value;
                }
                else if (curr.StartsWith("P"))
                {
                    // Param Arg Name
                    var m = Regex.Match(curr, @"P\[(\@\S+?)\].*", RegexOptions.Compiled).Groups;
                    if (m[1].Value == "")
                    {
                        Program.Log(LogLevel.WARN,
                            @"Failed to parse ""P"" option",
                            "Captured: [" + string.Join(", ", m) + "]",
                            "Raw: " + curr
                        );
                        continue;
                    }
                    paramInfo["param"] = m[1].Value;
                }
                else
                {
                    Program.Log(LogLevel.WARN,
                        $"Skipped unknown info [{args[i]}]"
                    );
                }
            }

            return (args[1], paramInfo);
        }
    }
}
