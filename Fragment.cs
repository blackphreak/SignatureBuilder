using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SignatureBuilder
{
    public class Fragment : ParserCode
    {
        public static Dictionary<string, Fragment> FragmentPool = new Dictionary</*name*/string, Fragment>();

        public string Name;
        public string Signature = "";
        public List<dynamic> Infos = new List<dynamic>();

        private bool isSignatureBuilt = false;

        public Fragment(string name)
        {
            this.Name = name;
        }

        public override void BuildSignature()
        {
            if (isSignatureBuilt)
                return;

            Program.Log(LogLevel.NOR, "Building Signature for Fragment[" + Name + "]");

            foreach (var (num, code) in this.Lines)
            {
                var (sign, infos) = ParseSignatureLine(code);
                Program.currentLine = num;

                if (infos != null)
                {
                    // "pad-<sz>" is already included in ParseSignatureLine()
                    Signature += " " + sign;
                    Infos.Add(infos);
                }
                else
                {
                    // for "Fragment", code could be one of these:
                    // + Fragment[       // fragment within fragment

                    if (code.StartsWith("+ Fragment"))
                    {
                        var obj = Fragment.GetFragmentByCode(code);

                        Signature += " " + obj.Signature;
                        Infos.AddRange(obj.Infos);
                    }
                    else if (code.StartsWith("+ REP"))
                    {
                        Signature += " [REPS]";
                    }
                    else if (code.StartsWith("- REP"))
                    {
                        Signature += " [REPE]";
                    }
                    else
                    {
                        Program.Log(LogLevel.ERR | LogLevel.EXIT,
                            "Invalid code for \"Fragment\".",
                            "Raw: " + code);
                    }
                }
            }

            Signature = Signature.Trim();
            isSignatureBuilt = true;
        }

        public static Fragment GetFragmentByCode(string code)
        {
            var m = ParserCode.regexFrag.Match(code).Groups;

            if (m[1].Value == "")
            {
                Program.Log(LogLevel.ERR | LogLevel.EXIT,
                    "Failed to capture Fragment name.",
                    "Captured: {" + string.Join(", ", m) + "}",
                    "Raw: " + code);
            }

            Fragment obj;
            if (!Fragment.FragmentPool.TryGetValue(m[1].Value, out obj))
            {
                Program.Log(LogLevel.ERR | LogLevel.EXIT,
                    "\"Fragment\" referenced before assignment.",
                    "Fragment Name: " + m[1].Value,
                    "Raw: " + code);
            }

            // ask to build signature if not yet built before.
            if (!obj.isSignatureBuilt)
                obj.BuildSignature();

            return obj;
        }
    }
}
