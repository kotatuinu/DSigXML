using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Xml;
using XMLDSig;
using static XMLDSig.XMLDigitalSignature;

namespace DSigXML
{
    public class DSigXML
{
        public static void Main(string[] args)
    {
        // 引数解析
        DSigXMLArgsAnalyzer obj = new DSigXMLArgsAnalyzer();
        Dictionary<string, string> argList = obj.ConvertArgs(args);
        if (argList == null)
        {
            Console.WriteLine("No arguments provided.");
            return;
        }


        XMLDigitalSignature xmlDSig = new XMLDigitalSignature();

        // パラメタ別の分岐
        if (argList.ContainsKey("s"))
        {
            if (argList.Count == 5)
            {
                // 署名付与（電子証明書ファイル）
                xmlDSig.Sign(argList["f"], argList["p"], argList["s"], argList["id"], argList["o"]);
            }
            else if (argList.Count == 4)
            {
                // 署名付与（ICカード）
                xmlDSig.SignIC(argList["pr"], argList["s"], argList["id"], argList["o"]);
            }
            xmlDSig.Verfy(argList["o"]);
        }
        else if (argList.ContainsKey("v"))
        {
            // 署名検証
            xmlDSig.Verfy(argList["v"]);
        }
        else if (argList.ContainsKey("ix"))
        {
            // 動作検証：署名付きXMLの証明書情報取得
            var xmlDoc = new XmlDocument();
            xmlDoc.PreserveWhitespace = true;
            xmlDoc.Load(argList["ix"]);
            var list = xmlDoc.GetElementsByTagName("X509Certificate", "*");
            if (list.Count == 0)
            {
                Console.WriteLine("No X509Certificate.");
                return;
            }
                for (int i = 0; i < list.Count; i++)
            {
                Console.WriteLine("X509Certificate[{0}]", i);
                string x509certText = list[i].InnerText;
                var x509 = new X509Certificate2(Convert.FromBase64String(x509certText));
                xmlDSig.DispPropertyValue(x509);
            }
        }
        else if (argList.ContainsKey("if"))
        {
            // 動作検証：電子証明書ファイル証明書情報取得
            xmlDSig.DispSigInfo(argList["if"], argList["p"]);
        }
        else if (argList.ContainsKey("ii"))
        {
            // 動作検証：ICカード証明書情報取得
            xmlDSig.DispICCardX509(argList["ii"]);
        }
        else if (argList.ContainsKey("d"))
        {
            // 動作検証：ダイジェスト値生成
            TRANSFORM_KIND trfKind = TRANSFORM_KIND.DsigC14NTransform;
            if (TRANSFORM_KIND_ARGS.ContainsKey(argList["c"]))
            {
                trfKind = TRANSFORM_KIND_ARGS[argList["c"]];
            }
            DIGEST_KIND digestKind = DIGEST_KIND.SHA256;
            if (DIGEST_KIND_ARGS.ContainsKey(argList["dg"]))
            {
                digestKind = DIGEST_KIND_ARGS[argList["dg"]];
            }

            string result = xmlDSig.MakeDigestValue(argList["d"], argList["id"], trfKind, digestKind);
            Console.WriteLine(result);

        }
        else if (argList.ContainsKey("st"))
        {
            // 動作検証：ファイルの内容をダイジェスト→署名付与を行う（SignedInfo要素→SinatureValue要素の確認）
            if (argList.Count == 5)
            {
                // 署名付与シーケンス テスト
                xmlDSig.testSign(argList["f"], argList["p"], argList["st"]);
            }
            else if (argList.Count == 2)
            {
                // 署名付与シーケンス テスト（ICカード）
                // ファイルをバイナリで読み込む
                byte[] xmlData = File.ReadAllBytes(argList["st"]);
                xmlDSig.testSignIC(argList["pr"], xmlData);
            }
        }
        else
        {
            // Usage
            string[] usage = {
                    "署名付与・検証ツール",
                    "usage:",
                    "\t署名付与（電子証明書ファイル）: -s <XMLファイル名> -f <電子証明書ファイル名> -p <パスワード> -id <署名対象XML id属性値> -o <出力：署名付与XMLファイル名>",
                    "\t署名付与（ICカード）: -s <XMLファイル名> -pr <ICカードプロバイダ名> -id <署名対象XML id属性値> -o <出力：署名付与XMLファイル名>",
                    "\t署名検証: -v <署名付きXMLファイル名>",
                    "\t署名付きXMLの証明書情報参照: -ix <署名付きXML>",
                    "\t証明書情報参照（電子証明書ファイル）: -if <電子証明書ファイル名> -p <パスワード>",
                    "\t証明書情報参照（ICカード）: -ii <ICカードプロバイダ名>",
                    "\tダイジェスト作成: -d <XMLファイル名> -id <署名対象XML id属性値> -c <ダイジェスト方式>[DSIGC14|DSIGEXECC14] -dg [SHA1|SHA256|SHA384|SHA512]",
            };

            foreach (var s in usage)
            {
                Console.WriteLine(s);
            }
        }
    }
}
}