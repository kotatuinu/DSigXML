using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace DSigXML.Tests
{
    [TestClass()]
    public class DSigXMLArgsAnalyzerTests
    {
        [TestMethod()]
        public void ConvertArgsTest_OK_署名付与_電子証明書ファイル()
        {
            DSigXMLArgsAnalyzer obj = new DSigXMLArgsAnalyzer();
            var argList = obj.ConvertArgs(new string[] { "-s", "test.xml", "-f", "cert.pfx", "-p", "password", "-id", "ID", "-o", "output.xml" });
            Assert.IsNotNull(argList);
            Assert.IsTrue(argList.ContainsKey("s"));
            Assert.IsTrue(argList["s"] == "test.xml");
            Assert.IsTrue(argList.ContainsKey("f"));
            Assert.IsTrue(argList["f"] == "cert.pfx");
            Assert.IsTrue(argList.ContainsKey("p"));
            Assert.IsTrue(argList["p"] == "password");
            Assert.IsTrue(argList.ContainsKey("id"));
            Assert.IsTrue(argList["id"] == "ID");
            Assert.IsTrue(argList.ContainsKey("o"));
            Assert.IsTrue(argList["o"] == "output.xml");
        }

        [TestMethod()]
        public void ConvertArgsTest_OK_署名付与_ICカード()
        {
            DSigXMLArgsAnalyzer obj = new DSigXMLArgsAnalyzer();
            var argList = obj.ConvertArgs(new string[] { "-s", "test.xml", "-pr", "JPKI Crypto Service Provider for Sign", "-id", "ID", "-o", "output.xml" });
            Assert.IsNotNull(argList);
            Assert.IsTrue(argList.ContainsKey("s"));
            Assert.IsTrue(argList["s"] == "test.xml");
            Assert.IsTrue(argList.ContainsKey("pr"));
            Assert.IsTrue(argList["pr"] == "JPKI Crypto Service Provider for Sign");
            Assert.IsTrue(argList.ContainsKey("id"));
            Assert.IsTrue(argList["id"] == "ID");
            Assert.IsTrue(argList.ContainsKey("o"));
            Assert.IsTrue(argList["o"] == "output.xml");
        }

        [TestMethod()]
        public void ConvertArgsTest_OK_署名付きXML証明書情報取得()
        {
            DSigXMLArgsAnalyzer obj = new DSigXMLArgsAnalyzer();
            var argList = obj.ConvertArgs(new string[] { "-ix", "test.xml" });
            Assert.IsNotNull(argList);
            Assert.IsTrue(argList.ContainsKey("ix"));
            Assert.IsTrue(argList["ix"] == "test.xml");
        }

        [TestMethod()]
        public void ConvertArgsTest_OK_証明書情報取得_電子証明書ファイル()
        {
            DSigXMLArgsAnalyzer obj = new DSigXMLArgsAnalyzer();
            var argList = obj.ConvertArgs(new string[] { "-if", "cert.pfx", "-p", "password" });
            Assert.IsNotNull(argList);
            Assert.IsTrue(argList.ContainsKey("if"));
            Assert.IsTrue(argList["if"] == "cert.pfx");
            Assert.IsTrue(argList.ContainsKey("p"));
            Assert.IsTrue(argList["p"] == "password");
        }

        [TestMethod()]
        public void ConvertArgsTest_OK_証明書情報取得_ICカード()
        {
            DSigXMLArgsAnalyzer obj = new DSigXMLArgsAnalyzer();
            var argList = obj.ConvertArgs(new string[] { "-ii", "JPKI Crypto Service Provider for Sign" });
            Assert.IsNotNull(argList);
            Assert.IsTrue(argList.ContainsKey("ii"));
            Assert.IsTrue(argList["ii"] == "JPKI Crypto Service Provider for Sign");
        }

        [TestMethod()]
        public void ConvertArgsTest_OK_署名検証()
        {
            DSigXMLArgsAnalyzer obj = new DSigXMLArgsAnalyzer();
            var argList = obj.ConvertArgs(new string[] { "-v", "test.xml" });
            Assert.IsNotNull(argList);
            Assert.IsTrue(argList.ContainsKey("v"));
            Assert.IsTrue(argList["v"] == "test.xml");
        }

        [TestMethod()]
        public void ConvertArgsTest_OK_ダイジェスト値作成()
        {
            DSigXMLArgsAnalyzer obj = new DSigXMLArgsAnalyzer();
            var argList = obj.ConvertArgs(new string[] { "-d", "test.xml", "-dg", "SHA256", "-id", "ID", "-c", "DSIGC14" });
            Assert.IsNotNull(argList);
            Assert.IsTrue(argList.ContainsKey("d"));
            Assert.IsTrue(argList["d"] == "test.xml");
            Assert.IsTrue(argList.ContainsKey("dg"));
            Assert.IsTrue(argList["dg"] == "SHA256");
            Assert.IsTrue(argList.ContainsKey("id"));
            Assert.IsTrue(argList["id"] == "ID");
            Assert.IsTrue(argList.ContainsKey("c"));
            Assert.IsTrue(argList["c"] == "DSIGC14");
        }

        [TestMethod()]
        public void ConvertArgsTest_NG1()
        {
            DSigXMLArgsAnalyzer obj = new DSigXMLArgsAnalyzer();
            var argList = obj.ConvertArgs(new string[] { "-stest.xml", "-fcert.pfx", "-ppassword", "-idID", "-ooutput.xml" });
            Assert.IsNull(argList);
        }

        [TestMethod()]
        public void ConvertArgsTest_collision1()
        {
            DSigXMLArgsAnalyzer obj = new DSigXMLArgsAnalyzer();
            var argList = obj.ConvertArgs(new string[] { "-s", "test.xml", "-f", "cert.pfx", "-p", "password", "-id", "ID", "-o", "output.xml", "-ix", "cert.p12" });
            Assert.IsNull(argList);
        }

        [TestMethod()]
        public void ConvertArgsTest_collision2()
        {
            DSigXMLArgsAnalyzer obj = new DSigXMLArgsAnalyzer();
            var argList = obj.ConvertArgs(new string[] { "-s", "test.xml", "-f", "cert.pfx", "-p", "password", "-id", "ID", "-o", "output.xml", "-v", "cert.p12" });
            Assert.IsNull(argList);
        }

        [TestMethod()]
        public void ConvertArgsTest_collision3()
        {
            DSigXMLArgsAnalyzer obj = new DSigXMLArgsAnalyzer();
            var argList = obj.ConvertArgs(new string[] { "-s", "test.xml", "-f", "cert.pfx", "-p", "password", "-id", "ID", "-o", "output.xml", "-d", "cert.p12" });
            Assert.IsNull(argList);
        }

        [TestMethod()]
        public void ConvertArgsTest_collision4()
        {
            DSigXMLArgsAnalyzer obj = new DSigXMLArgsAnalyzer();
            var argList = obj.ConvertArgs(new string[] { "-ix", "test.xml", "-v", "cert.pfx"});
            Assert.IsNull(argList);
        }

        [TestMethod()]
        public void ConvertArgsTest_collision5()
        {
            DSigXMLArgsAnalyzer obj = new DSigXMLArgsAnalyzer();
            var argList = obj.ConvertArgs(new string[] { "-if", "test.xml", "-d", "cert.pfx" });
            Assert.IsNull(argList);
        }

        [TestMethod()]
        public void ConvertArgsTest_collision6()
        {
            DSigXMLArgsAnalyzer obj = new DSigXMLArgsAnalyzer();
            var argList = obj.ConvertArgs(new string[] { "-ii", "test.xml", "-d", "cert.pfx" });
            Assert.IsNull(argList);
        }

        [TestMethod()]
        public void ConvertArgsTest_collision7()
        {
            DSigXMLArgsAnalyzer obj = new DSigXMLArgsAnalyzer();
            var argList = obj.ConvertArgs(new string[] { "-v", "test.xml", "-d", "cert.pfx" });
            Assert.IsNull(argList);
        }
    }
}