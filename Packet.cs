using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SignatureBuilder
{
    public class Packet : ParserCode
    {
        public static Dictionary<string, Packet> PacketPool = new Dictionary</*hex*/string, Packet>();
        private static readonly JObject ParamPlaceholderName = new JObject() { { "name", "-" } };

        public string Desc;
        public string Header {
            get;
            private set;
        }
        public JObject Signatures = new JObject();

        /// <summary>
        /// subcate signature : {desc, param:[{...}, {...}, ...]}
        /// </summary>
        private Dictionary</*sign*/string, /*subcate infos*/JObject> subcate = new Dictionary<string, JObject>();
        private bool isSignatureBuilt = false;

        public Packet(string desc, string headerHex)
        {
            this.Desc = desc;
            this.Header = headerHex;
        }

        public override void BuildSignature()
        {
            if (isSignatureBuilt)
                return;

            Program.Log(LogLevel.NOR, "Building Signature for Packet[" + Header.PadRight(4, ' ') + "][" + Desc + "]");

            bool doesSubcatePlaceholderAppeared = false;
            bool packetBodySectionEnded = false;
            bool isInSubcate = false;
            bool isRepeatableTagEnded = true;
            string tmpSignature = ""; // subcate is not replaced yet
            JArray infoBeforeSubcate = new JArray();
            JArray infoAfterSubcate = new JArray();

            dynamic tmpObj = new JObject();
            string tmpSubcateSignature = "";
            JArray tmpSubcateInfo = new JArray();

            foreach (var (num, code) in Lines)
            {
                var (sign, infos) = ParseSignatureLine(code);
                Program.currentLine = num;

                if (infos != null)
                {
                    if (isInSubcate)
                    {
                        tmpSubcateSignature += " " + sign;
                        tmpSubcateInfo.Add(infos);
                    }
                    else
                    {
                        tmpSignature += " " + sign;
                        if (doesSubcatePlaceholderAppeared)
                            infoAfterSubcate.Add(infos);
                        else
                            infoBeforeSubcate.Add(infos);
                    }
                }
                else
                {
                    if (code.StartsWith("+ Fragment"))
                    {
                        var obj = Fragment.GetFragmentByCode(code);

                        tmpSignature += " " + obj.Signature;
                        // add range
                        obj.Infos.ForEach(info => infoBeforeSubcate.Add(info));
                    }
                    else if (code.StartsWith("+ SubCate"))
                    {
                        // set constraint, only 1 subcate code can be used
                        if (doesSubcatePlaceholderAppeared)
                        {
                            Program.Log(LogLevel.ERR | LogLevel.EXIT,
                                "Constraint Violation - You can only use 1 \"+ SubCate\" within same packet/fragment.",
                                "Occurred within: Packet[" + Header.PadRight(4, ' ') + "] " + Desc
                            );
                        }
                        else if (packetBodySectionEnded)
                        {
                            Program.Log(LogLevel.ERR | LogLevel.EXIT,
                                "Constraint Violation - You cannot include another subcate within a subcate.",
                                "Occurred within: Packet[" + Header.PadRight(4, ' ') + "] " + Desc
                            );
                        }

                        tmpSignature += " {SUBCATE}";
                        doesSubcatePlaceholderAppeared = true;
                    }
                    else if (code.StartsWith("SubCate["))
                    {
                        // start of subcate signature
                        var m = regexSubcate.Match(code);
                        var g = m.Groups;
                        if (!m.Success || (g[1].Value == "" && g[2].Value == ""))
                        {
                            Program.Log(LogLevel.ERR | LogLevel.EXIT,
                                "Invalid SubCate declaration.",
                                "Occurred within: Packet[" + Header.PadRight(4, ' ') + "] " + Desc,
                                "Captured: [" + string.Join(", ", g.Values) + "]",
                                "Raw: " + code
                            );
                        }

                        // have subcate before this subcate (another)
                        // push the previous subcate to dict list
                        if (isInSubcate)
                        {
                            if (tmpSignature == "")
                            {
                                Program.Log(LogLevel.WARN,
                                    "Skipped invalid SubCate declaration - No actual signature/body.",
                                    "Occurred within: Packet[" + Header.PadRight(4, ' ') + "] " + Desc
                                );
                            }
                            else
                                subcate.Add(tmpSubcateSignature.TrimStart(), tmpObj);
                        }

                        tmpObj = new JObject(); // renew
                        tmpObj.desc = g[1].Value;
                        tmpObj["params"] = tmpSubcateInfo = new JArray();
                        tmpSubcateSignature = "";

                        if (g[2].Value != "")
                        {
                            // with hex-byte (static hex subcate signature)
                            tmpSubcateSignature += " " + g[2].Value[1..];
                            tmpSubcateInfo.Add(new JObject() {
                                { "name", "- SubCate -" }
                            });
                        }
                        Program.Log(LogLevel.NOR, 1, $"New Subcate[{tmpObj.desc}]");
                        isInSubcate = true;
                    }
                    else if (code == "pack")
                    {
                        packetBodySectionEnded = true;
                    }
                    else if (code.StartsWith("+ REP"))
                    {
                        if (!isRepeatableTagEnded)
                        {
                            Program.Log(LogLevel.ERR | LogLevel.EXIT,
                                "Cannot use \"+ REP\" (start tag) before the previous repeatable start tag ends.",
                                "Occurred within: Packet[" + Header.PadRight(4, ' ') + "] " + Desc
                            );
                        }
                        else if (packetBodySectionEnded && !isInSubcate)
                        {
                            Program.Log(LogLevel.ERR | LogLevel.EXIT,
                                "You cannot use repeatable tag (+ REP) while outside Packet/Subcate body.",
                                "Occurred within: Packet[" + Header.PadRight(4, ' ') + "] " + Desc
                            );
                        }

                        if (isInSubcate)
                        {
                            tmpSubcateSignature += " [REPS]";
                            tmpSubcateInfo.Add(ParamPlaceholderName);
                        }
                        else
                        {
                            tmpSignature += " [REPS]";
                            if (doesSubcatePlaceholderAppeared)
                                infoAfterSubcate.Add(ParamPlaceholderName);
                            else
                                infoBeforeSubcate.Add(ParamPlaceholderName);
                        }

                        isRepeatableTagEnded = false;
                    }
                    else if (code.StartsWith("- REP"))
                    {
                        if (isRepeatableTagEnded)
                        {
                            Program.Log(LogLevel.ERR | LogLevel.EXIT,
                                "Cannot use \"- REP\" (end tag) before \"+ REP\" (start tag).",
                                "Occurred within: Packet[" + Header.PadRight(4, ' ') + "] " + Desc
                            );
                        }
                        else if (packetBodySectionEnded && !isInSubcate)
                        {
                            Program.Log(LogLevel.ERR | LogLevel.EXIT,
                                "You cannot use repeatable tag (- REP) while outside Packet/Subcate body.",
                                "Occurred within: Packet[" + Header.PadRight(4, ' ') + "] " + Desc
                            );
                        }

                        if (isInSubcate)
                        {
                            tmpSubcateSignature += " [REPE]";
                            tmpSubcateInfo.Add(ParamPlaceholderName);
                        }
                        else
                        {
                            tmpSignature += " [REPE]";
                            if (doesSubcatePlaceholderAppeared)
                                infoAfterSubcate.Add(ParamPlaceholderName);
                            else
                                infoBeforeSubcate.Add(ParamPlaceholderName);
                        }

                        isRepeatableTagEnded = true;
                    }
                    else
                    {
                        Program.Log(LogLevel.ERR | LogLevel.EXIT,
                            "Invalid code for \"Fragment\".",
                            "Raw: " + code);
                    }
                }
            }

            if (doesSubcatePlaceholderAppeared)
            {
                // pack the final subcate
                if (isInSubcate)
                    subcate.Add(tmpSubcateSignature.TrimStart(), tmpObj);

                tmpSignature = tmpSignature.Trim();
                // replace {SUBCATE} with actual subcate signature & its infos
                foreach (var (sign, subcateInfos) in this.subcate)
                {
                    // {desc, params:[<mergedParams>]}
                    JObject mergedInfos = new JObject();
                    var mergedParams = new JArray();
                    mergedInfos.Add("params", mergedParams);
                    mergedInfos.Add("desc", subcateInfos.Value<string>("desc"));

                    foreach (var info in infoBeforeSubcate)
                        mergedParams.Add(info);

                    foreach (var info in subcateInfos.Value<dynamic>("params"))
                        mergedParams.Add(info);

                    foreach (var info in infoAfterSubcate)
                        mergedParams.Add(info);

                    Signatures.Add((tmpSignature.Clone() as string).Replace("{SUBCATE}", sign), mergedInfos);
                }
            }
            else
            {
                // no subcate
                Signatures.Add(tmpSignature.Trim(), new JObject() {
                    { "params" , infoBeforeSubcate }
                });
            }

            isSignatureBuilt = true;
        }
    }
}


/**
    + SubCate   // subcate body
    + Fragment[ // fragment in main body
    pack        // end of all signature
    EOP         // end of packet -- force pack even without signature
    // lower part:
    SubCate[     // subcate declaration
    + Fragment[  // fragment in subcate


 else if (line.StartsWith("+ SubCate"))
{
    pkt.rawSignatureBeforeParse.Add("{SUBCATE}");
    pkt.SubCate = new Dictionary<string, dynamic>();
}
else if (line.StartsWith("+ Fragment["))
{
    var matches = regexFrag.Match(line);
    if (matches.Groups.Count != 2)
    {
        Log(LogLevel.ERR | LogLevel.EXIT,
            "Malform Fragment tag found.",
            "Captured: [" + string.Join(", ", matches.Groups.Values) + "]",
            "Raw: " + line
        );
    }

    dynamic frag;
    if (!fragmentPool.TryGetValue(matches.Groups[1].Value, out frag))
    {
        Log(LogLevel.ERR | LogLevel.EXIT,
            "Fragment referenced before assignment.",
            "Referenced Fragment Name: " + matches.Groups[1].Value,
            "Raw: " + line
        );
    }
    pkt.UsedFragment.Add(matches.Groups[1].Value, frag);
}
else if (line == "pack")
{
    // end of packet content
    pkt.Pack();
}
else if (line.StartsWith("SubCate["))
{
    // subcate declaration
    var captured = regexSubcate.Match(line).Groups;
    if (captured.Count != 4 && captured.Count != 2)
    {
        Log(LogLevel.ERR | LogLevel.EXIT,
            "Invalid SubCate Declaration found.",
            $"Expected Groups Count: 2 / 4, Actual: {captured.Count}",
            "Capture Groups: {" + string.Join(", ", captured.Values.SelectMany(x => x.Value)) + "}",
            "Raw: " + line
        );
    }

    var _byte = captured[4]?.Value ?? null;
    if (currentSubcate[0] == captured[1].Value)
    {
        Log(LogLevel.ERR | LogLevel.EXIT,
            "Duplicated SubCate Description within the same Packet.",
            $"Previous: \"{string.Join("\" : ", currentSubcate)}",
            $"Current: \"{captured[1].Value}\" : {_byte ?? "-N/A-"}"
        );
    }
    else if (captured[4] != null && currentSubcate[1] == captured[4].Value)
    {
        Log(LogLevel.ERR | LogLevel.EXIT,
            "Duplicated SubCate Byte within the same Packet.",
            $"Previous: {string.Join(" : \"", currentSubcate)}\"",
            $"Current: {captured[1].Value} : \"{_byte ?? "-N/A-"}\""
        );
    }

    if (!Regex.IsMatch(_byte, @"\A\b[0-9a-fA-F]+\b\Z"))
    {
        Log(LogLevel.ERR | LogLevel.EXIT,
            "Non-hex value provided as signature byte for SubCate",
            $"Provided: {_byte}"
        );
    }

    currentSubcate = new string[] { captured[1].Value, _byte };

    dynamic info = new JObject();
info.desc = captured[1].Value;
    info["params"] = new JArray();

    if (captured.Count == 4)
    {
        // fixed byte
        info._tmpSign = _byte; // TODO: remove it before json output
    }
    // else: with desc only
    // ~ do nothing

    if (!pkt.SubCate.TryAdd(*//*desc*//*captured[1].Value, info))
    {
        Log(LogLevel.ERR | LogLevel.EXIT,
            $"Failed to add SubCate with description[{captured[1].Value}]"
        );
    }
}
*/
