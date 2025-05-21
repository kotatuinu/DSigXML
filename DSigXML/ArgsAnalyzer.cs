using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace DSigXML
{
    public class ArgsAnalyzer
    {
        protected Dictionary<string, List<List<string>>> argList_;

        private List<string> GetCommandParam(Dictionary<string, List<List<string>>> argList)
        {
            var result = new List<string>();
            foreach (var arg in argList)
            {
                foreach (var item in arg.Value)
                {
                    foreach (var item2 in item)
                    {
                        if (!result.Exists(x => x == item2))
                        {
                            result.Add(item2);
                        }
                    }
                }
            }
            return result;
        }

        private List<string> GetCommandTop(Dictionary<string, List<List<string>>> argList)
        {
            var result = new List<string>();
            foreach (var item in argList.Keys)
            {
                if (!result.Exists(x => x == item))
                {
                    result.Add(item);
                }
            }
            return result;
        }

        public Dictionary<string, string> ConvertArgs(string[] args)
        {
            Dictionary<string, string> result = new Dictionary<string, string>();
            var itemList = GetCommandParam(argList_);
            string rgxStr = "^-(" + string.Join("|", itemList) + ")$";

            var rgx = new Regex(rgxStr);

            for (int idx = 0; idx < args.Length; idx++)
            {
                foreach (Match m in rgx.Matches(args[idx]))
                {
                    if (idx + 1 >= args.Length)
                    {
                        // エラー
                        Console.WriteLine("Invalid Argument.");
                        return null;
                    }

                    result[m.Groups[1].Value] = args[idx + 1];
                    idx++;
                }
            }
            if (result.Count == 0)
            {
                // エラー
                Console.WriteLine("Invalid Argument.");
                return null;
            }

            string topParam = "";
            List<string> topList = GetCommandTop(argList_);
            // 排他チェック s,i,v,dは排他
            int cnt = 0;
            foreach (var w in topList)
            {
                if (result.ContainsKey(w))
                {
                    topParam = w;
                    cnt++;
                }
            }
            if (cnt != 1)
            {
                // エラー
                Console.WriteLine("Invalid Argument.");
                return null;
            }

            // 引数が全てそろっているかチェック
            bool isArgCheckOK = false;
            foreach (var keys in argList_[topParam])
            {
                bool isOK = true;
                foreach (var k in keys)
                {
                    if (!result.ContainsKey(k))
                    {
                        // エラー
                        isOK = false;
                        break;
                    }
                }
                if (isOK)
                {
                    isArgCheckOK = true;
                    break;
                }
            }
            if (!isArgCheckOK)
            {
                // エラー
                Console.WriteLine("Invalid Argument.");
                return null;
            }

            return result;
        }
    }

    public class DSigXMLArgsAnalyzer : ArgsAnalyzer
    {
        //・署名付与（電子証明書ファイル）: -s <XMLファイル名> -f <電子証明書ファイル名> -p <パスワード> -id <署名付与対象ID属性値> -o <出力：署名付与XMLファイル名>
        //・署名付与（ICカード）: -s <XMLファイル名> -pr <ICカードプロバイダ名> -id <署名付与対象ID属性値> -o <出力：署名付与XMLファイル名>
        //・署名付きXMLの証明書情報取得: -ix <電子証明書ファイル名> -p <パスワード>
        //・証明書情報取得（電子証明書ファイル）: -if <電子証明書ファイル名> -p <パスワード>
        //・証明書情報取得（ICカード）: -ii <ICカードプロバイダ名>
        //・署名検証: -v <署名付きXMLファイル名> 
        //・ダイジェスト値作成: -d <XMLファイル名> -id <署名付与対象ID属性値> -c <正規化変換方式> -dg <ダイジェスト方式> 
        //・署名テスト（ファイル）: -st <XMLファイル名> -f <電子証明書ファイル名> -p <パスワード>
        //・署名テスト（ICカード）: -st <XMLファイル名> -pr <ICカードプロバイダ名>

        public DSigXMLArgsAnalyzer()
        {

            argList_ = new Dictionary<string, List<List<string>>> {
                { "s", new List<List<string>> {
                        new List<string>{ "s", "f", "p", "id", "o" },   // 署名付与（電子証明書ファイル）
                        new List<string>{ "s", "pr", "id", "o" },   // 署名付与（ICカード）
                    } },
                { "ix", new List<List<string>> {
                            new List<string> { "ix"},   // 署名付きXMLの証明書情報取得
                        } },
                { "if", new List<List<string>> {
                            new List<string> { "if", "p" }, // 証明書情報取得（電子証明書ファイル）
                        } },
                { "ii", new List<List<string>> {
                            new List<string> { "ii"},   // 証明書情報取得（ICカード）
                        } },
                { "v", new List<List<string>> {
                      new List<string> { "v" }, // 署名検証
                    } },
                { "d", new List<List<string>> {
                      new List<string> { "d", "id", "c", "dg" },    // ダイジェスト値作成
                    } },
                { "st", new List<List<string>> {
                        new List<string>{ "st", "f", "p" }, // 署名テスト（ファイル）
                        new List<string>{ "st", "pr" },     // 署名テスト（ICカード）
                    } },
            };
        }

    }
}
