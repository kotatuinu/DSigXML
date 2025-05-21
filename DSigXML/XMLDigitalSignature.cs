using CryptoAPI;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Security.Cryptography;
using System.Xml;
using VerfySignedXML;

namespace XMLDSig
{
    internal class XMLDigitalSignature
    {
        public void DispSigInfo(String filename, string password)
        {
            try
            {
                var x509 = new X509Certificate2(filename, password, X509KeyStorageFlags.Exportable);
                DispPropertyValue(x509);
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }
        }

        public void DispFileX509(string filename, string password)
        {
            var x509 = new X509Certificate2(filename, password, X509KeyStorageFlags.Exportable);
            DispPropertyValue(x509);
        }

        public void DispICCardX509(string provider)
        {
            var provInfo = SmartCardBuilder.CspParamterBuilder(provider);
            CryptoApiAsymmetricAlgorithm caaa = new CryptoApiAsymmetricAlgorithm(provider, (uint)provInfo.ProviderType);
            var x509 = caaa.GetUserKey();
            DispPropertyValue(x509);

        }

        public enum TRANSFORM_KIND
        {
            DsigC14NTransform,
            DsigExcC14NTransform,
        };
        public static Dictionary<string, TRANSFORM_KIND> TRANSFORM_KIND_ARGS = new Dictionary<string, TRANSFORM_KIND>{
            { "DSIGC14", TRANSFORM_KIND.DsigC14NTransform},
            { "DSIGEXECC14", TRANSFORM_KIND.DsigExcC14NTransform},
        };

        public enum DIGEST_KIND
        {
            //MD5,
            SHA1,
            SHA256,
            SHA384,
            SHA512,
        }
        public static Dictionary<string, DIGEST_KIND> DIGEST_KIND_ARGS = new Dictionary<string, DIGEST_KIND>{
            { "SHA1", DIGEST_KIND.SHA1},
            { "SHA256", DIGEST_KIND.SHA256},
            { "SHA384", DIGEST_KIND.SHA384},
            { "SHA512", DIGEST_KIND.SHA512},
        };

        public string MakeDigestValue(string xmlFilename, string id, TRANSFORM_KIND trnsFrmKind, DIGEST_KIND digestKind)
        {
            string base64Val = "";
            try
            {
                var xmlDoc = new XmlDocument();
                xmlDoc.PreserveWhitespace = true;
                xmlDoc.Load(xmlFilename);
                var list = xmlDoc.SelectNodes(string.Format(@"//*[contains(@id, '{0}')]", id));
                if (list.Count == 0)
                {
                    Console.WriteLine("No Exists spacify id.");
                    return "";
                }
                xmlDoc.LoadXml(list[0].OuterXml);

                var trnsfDES = new XmlDsigEnvelopedSignatureTransform();
                trnsfDES.Algorithm = SignedXml.XmlDsigEnvelopedSignatureTransformUrl;
                var elm = trnsfDES.GetXml();
                trnsfDES.LoadInput(xmlDoc);
                XmlDocument xmlDocumentOutput = (XmlDocument)trnsfDES.GetOutput(typeof(XmlDocument));

                // XMLの正規化 canonicalization
                Transform trnsf;
                switch (trnsFrmKind)
                {
                    case TRANSFORM_KIND.DsigExcC14NTransform:
                        trnsf = new XmlDsigExcC14NTransform();  // http://www.w3.org/2001/10/xml-exc-c14n#
                        break;
                    case TRANSFORM_KIND.DsigC14NTransform:
                    default:
                        trnsf = new XmlDsigC14NTransform(); // http://www.w3.org/TR/2001/REC-xml-c14n-20010315
                        break;
                }

                trnsf.LoadInput(xmlDocumentOutput);
                var ms = (MemoryStream)trnsf.GetOutput(typeof(CryptoStream));
                //Console.WriteLine("[" + Encoding.UTF8.GetString(ms.ToArray()) +"]");


                using (Stream canonicalizedStream = (Stream)trnsf.GetOutput(typeof(Stream)))
                {
                    StreamReader reader = new StreamReader(canonicalizedStream);
                    string canonicalizedXml = reader.ReadToEnd();
                }

                // ハッシュ値算出：SHA1
                HashAlgorithm hashM;
                switch (digestKind)
                {
                    case DIGEST_KIND.SHA1:
                        hashM = SHA1.Create();
                        // 以下も同じ
                        //new SHA1Cng();
                        //new SHA1CryptoServiceProvider();
                        break;
                    case DIGEST_KIND.SHA384:
                        hashM = SHA384.Create();
                        break;
                    case DIGEST_KIND.SHA512:
                        hashM = SHA512.Create();
                        break;
                    case DIGEST_KIND.SHA256:
                    default:
                        hashM = SHA256.Create();
                        break;
                }

                var hashVal = hashM.ComputeHash(ms);
                base64Val = Convert.ToBase64String(hashVal);
                //Console.WriteLine(base64Val);
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }

            return base64Val;
        }


        public void Sign(String cerFileName, string password, string xmlFilename, string id, string signedXmlFilename)
        {
            try
            {
                var xmlDoc = new XmlDocument();
                xmlDoc.PreserveWhitespace = true;
                xmlDoc.Load(xmlFilename);
                var list = xmlDoc.SelectNodes(string.Format(@"//*[@id='{0}']", id));
                if (list.Count == 0)
                {
                    Console.WriteLine("No Exists spacify id.");
                    return;
                }

                var x509 = new X509Certificate2(cerFileName, password, X509KeyStorageFlags.Exportable);
                var signedXml = SignXml(xmlDoc, x509, id);

                list.Item(list.Count - 1).AppendChild(xmlDoc.ImportNode(signedXml, true));

                xmlDoc.Save(signedXmlFilename);
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }
        }
        public XmlElement SignXml(XmlDocument xmlDoc, X509Certificate2 x509, string uri)
        {
            if (xmlDoc == null)
            {
                throw new ArgumentException("xmlDoc");
            }
            if (x509 == null)
            {
                throw new ArgumentException("x509");
            }

            var signedXml = new PrefixedSignedXML(xmlDoc);
            signedXml.SigningKey = x509.GetRSAPrivateKey();
            signedXml.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;
            //signedXml.SignedInfo.SignatureMethod = SignedXml.XmlDsigRSASHA256Url;
            signedXml.SignedInfo.SignatureMethod = null;

            var reference = new Reference();
            reference.Uri = "#" + uri;

            var env = new XmlDsigEnvelopedSignatureTransform();
            reference.AddTransform(env);

            signedXml.AddReference(reference);

            var keyInfo = new KeyInfo();
            keyInfo.AddClause(new KeyInfoX509Data(x509));
            signedXml.KeyInfo = keyInfo;

            signedXml.ComputeSignature("dsig");
            return signedXml.GetXml();
        }

        public void SignIC(string provider, string xmlFilename, string id, string signedXmlFilename)
        {
            try
            {
                var xmlDoc = new XmlDocument();
                xmlDoc.PreserveWhitespace = true;
                xmlDoc.Load(xmlFilename);
                var list = xmlDoc.SelectNodes(string.Format(@"//*[@id='{0}']", id));
                if (list.Count == 0)
                {
                    Console.WriteLine("No Exists spacify id.");
                    return;
                }

                var provInfo = SmartCardBuilder.CspParamterBuilder(provider);
                CryptoApiAsymmetricAlgorithm caaa = new CryptoApiAsymmetricAlgorithm(provider, (uint)provInfo.ProviderType);
                var x509 = caaa.GetUserKey();

                var signedXml = SignXMLWithICCard(xmlDoc, caaa, id);

                list.Item(list.Count - 1).ParentNode.AppendChild(xmlDoc.ImportNode(signedXml, true));

                xmlDoc.Save(signedXmlFilename);
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }
        }

        public XmlElement SignXMLWithICCard(XmlDocument xmlDoc, CryptoApiAsymmetricAlgorithm caaa, string uri)
        {
            if (xmlDoc == null)
            {
                throw new ArgumentException("xmlDoc");
            }

            var signedXml = new PrefixedSignedXMLICCard(caaa, xmlDoc);
            signedXml.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigCanonicalizationUrl;
            //signedXml.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;
            signedXml.SignedInfo.SignatureMethod = null;

            var reference = new Reference();
            reference.Uri = "#" + uri;

            var env = new XmlDsigEnvelopedSignatureTransform();
            reference.AddTransform(env);

            signedXml.AddReference(reference);

            var keyInfo = new KeyInfo();
            var x509 = caaa.GetUserKey();
            keyInfo.AddClause(new KeyInfoX509Data(x509));
            signedXml.KeyInfo = keyInfo;

            signedXml.ComputeSignature("dsig");
            dispRowData(signedXml.SignatureValue);
            string base64Val = Convert.ToBase64String(signedXml.SignatureValue);
            Console.WriteLine("SignatureVale={0}", base64Val);

            return signedXml.GetXml();
        }

        public void testSign(String cerFileName, string password, string xmlData)
        {
        }
        public void testSignIC(string provider, byte[] xmlData)
        {
            try
            {
                var provInfo = SmartCardBuilder.CspParamterBuilder(provider);
                CryptoApiAsymmetricAlgorithm caaa = new CryptoApiAsymmetricAlgorithm(provider, (uint)provInfo.ProviderType);
                var x509 = caaa.GetUserKey();
                DispPropertyValue(x509);

                HashAlgorithmName hashAlgorithm = HashAlgorithmName.SHA256;
                switch (caaa.GetUserKey().SignatureAlgorithm.Value)
                {
                    case CryptoAPI.OidDef.szOID_X957_SHA1DSA:
                        hashAlgorithm = HashAlgorithmName.SHA1;
                        break;
                    case CryptoAPI.OidDef.szOID_RSA_SHA1RSA:
                        hashAlgorithm = HashAlgorithmName.SHA1;
                        break;
                    case CryptoAPI.OidDef.szOID_RSA_SHA256RSA:
                        hashAlgorithm = HashAlgorithmName.SHA256;
                        break;
                    case CryptoAPI.OidDef.szOID_RSA_SHA384RSA:
                        hashAlgorithm = HashAlgorithmName.SHA384;
                        break;
                    case CryptoAPI.OidDef.szOID_RSA_SHA512RSA:
                        hashAlgorithm = HashAlgorithmName.SHA512;
                        break;
                }

                var signatureValue = caaa.SignData(xmlData, hashAlgorithm);
                dispRowData(signatureValue);

                string base64Val = Convert.ToBase64String(signatureValue);
                Console.WriteLine("SignatureVale={0}", base64Val);

            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }
        }
 
        public void Verfy(string signedXmlFilename)
        {
            try
            {
                var xmlDoc = new XmlDocument();
                xmlDoc.PreserveWhitespace = true;
                xmlDoc.Load(signedXmlFilename);

                var result = VerifyXml(xmlDoc);
                if (result)
                {
                    Console.WriteLine("The XML signature is valid.");
                }
                else
                {
                    Console.WriteLine("The XML signature is not valid.");
                }

            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }
        }

        public Boolean VerifyXml(XmlDocument Doc)
        {
            var signedXml = new SignedXml(Doc);
            var nodeList = Doc.GetElementsByTagName("Signature", "*");

            if (nodeList.Count <= 0)
            {
                throw new CryptographicException("Verification failed: No Signature was found in the document.");
            }
            if (nodeList.Count >= 2)
            {
                throw new CryptographicException("Verification failed: More that one signature was found for the document.");
            }
            var elm = (XmlElement)nodeList[0];
            signedXml.LoadXml(elm);
            var rtn = signedXml.CheckSignature();

            var x509certList = Doc.GetElementsByTagName("X509Certificate", "*");
            var x509certText = x509certList[0].InnerText;
            var x = new X509Certificate2(Convert.FromBase64String(x509certText));
            var ch = new X509Chain();
            //ch.ChainPolicy.RevocationMode = X509RevocationMode.Online;
            ch.ChainPolicy.RevocationMode = X509RevocationMode.Offline;
            //ch.ChainPolicy.RevocationFlag = X509RevocationFlag.EntireChain;
            var isChainOK = ch.Build(x);
            Console.WriteLine("Chain Build {0}", isChainOK);

            return rtn;
        }


        public void DispPropertyValue(X509Certificate2 x509)
        {
            Console.WriteLine("Archived={0}", x509.Archived);
            Console.WriteLine("FriendlyName={0}", x509.FriendlyName);
            Console.WriteLine("HasPrivateKey={0}", x509.HasPrivateKey);
            Console.WriteLine("Issuer={0}", x509.Issuer);
            Console.WriteLine("IssuerName={0}", x509.IssuerName);
            Console.WriteLine("NotAfter={0}", x509.NotAfter);
            Console.WriteLine("NotBefore={0}", x509.NotBefore);

            Console.WriteLine("PublicKey={0}", x509.PublicKey.ToString());

            Console.WriteLine("SerialNumber={0}", x509.SerialNumber);
            //Console.WriteLine("SignatureAlgorithm={0}", x509.SignatureAlgorithm);
            Console.WriteLine("SignatureAlgorithm.FriendlyName={0}", x509.SignatureAlgorithm.FriendlyName);
            Console.WriteLine("SignatureAlgorithm.Value={0}", x509.SignatureAlgorithm.Value);
            Console.WriteLine("Subject={0}", x509.Subject);
            Console.WriteLine("SubjectName={0}", x509.SubjectName);
            Console.WriteLine("Thumbprint={0}", x509.Thumbprint);
            Console.WriteLine("Version={0}", x509.Version);

            if (x509.PrivateKey != null)
            {
                Console.WriteLine("KeyExchangeAlgorithm={0}", x509.PrivateKey.KeyExchangeAlgorithm);
                Console.WriteLine("KeySize={0}", x509.PrivateKey.KeySize);
                foreach (var item in x509.PrivateKey.LegalKeySizes)
                {
                    Console.WriteLine("PrivateKey.LegalKeySizes={0}", item.MaxSize);
                    Console.WriteLine("PrivateKey.LegalKeySizes={0}", item.MinSize);
                    Console.WriteLine("PrivateKey.LegalKeySizes={0}", item.SkipSize);
                }
                Console.WriteLine("SignatureAlgorith={0}", x509.PrivateKey.SignatureAlgorithm);
            }
            else
            {
                Console.WriteLine("no PrivateKey");
            }

            Console.WriteLine("PublicKey.EncodedKeyValue.Oid.FriendlyName={0}", x509.PublicKey.EncodedKeyValue.Oid.FriendlyName);
            Console.WriteLine("PublicKey.EncodedKeyValue.Value={0}", x509.PublicKey.EncodedKeyValue);
            Console.Write("PublicKey.EncodedKeyValue.RawData=");
            dispRowData(x509.PublicKey.EncodedKeyValue.RawData);

            Console.WriteLine("PublicKey.EncodedParameters.Oid.FriendlyName={0}", x509.PublicKey.EncodedParameters.Oid.FriendlyName);
            Console.WriteLine("PublicKey.EncodedParameters.Value={0}", x509.PublicKey.EncodedParameters);
            Console.Write("PublicKey.EncodedParameters.RawData=");
            dispRowData(x509.PublicKey.EncodedParameters.RawData);

            Console.WriteLine("SubjectName.Name={0}", x509.SubjectName.Name);
            Console.WriteLine("SubjectName.Oid.FriendlyName={0}", x509.SubjectName.Oid.FriendlyName);
            Console.WriteLine("SubjectName.Oid.Value={0}", x509.SubjectName.Oid.Value);
            Console.Write("SubjectName.RawData=");
            dispRowData(x509.SubjectName.RawData);

            Console.Write("RawData=");
            dispRowData(x509.RawData);
        }

        private void dispRowData(byte[] data)
        {
            foreach (var d in data)
            {
                Console.Write("{0:X2}", d);
            }
            Console.WriteLine("");
        }

    }
}
