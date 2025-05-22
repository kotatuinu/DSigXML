// https://stackoverflow.com/questions/12219232/xml-signature-ds-prefix
using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.Xml;

namespace VerfySignedXML
{
    public class PrefixedSignedXMLICCard : SignedXml
    {
        internal static Dictionary<string, string> OID_DEF = new Dictionary<string, string>
        {
            { CryptoAPI.OidDef.szOID_X957_SHA1DSA, "http://www.w3.org/2000/09/xmldsig#dsa-sha1" },
            { CryptoAPI.OidDef.szOID_RSA_SHA1RSA, "http://www.w3.org/2000/09/xmldsig#rsa-sha1" },
            { CryptoAPI.OidDef.szOID_RSA_SHA256RSA, "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" },
            { CryptoAPI.OidDef.szOID_RSA_SHA384RSA, "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384" },
            { CryptoAPI.OidDef.szOID_RSA_SHA512RSA, "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512" }
        };

        public PrefixedSignedXMLICCard(CryptoAPI.CryptoApiAsymmetricAlgorithm cryptoApiAsymmetricAlgorithm, XmlDocument document)
            : base(document) => this.cryptoApiAsymmetricAlgorithm = cryptoApiAsymmetricAlgorithm;

        public PrefixedSignedXMLICCard(CryptoAPI.CryptoApiAsymmetricAlgorithm cryptoApiAsymmetricAlgorithm, XmlElement element)
            : base(element) => this.cryptoApiAsymmetricAlgorithm = cryptoApiAsymmetricAlgorithm;

        public PrefixedSignedXMLICCard()
            : base()
        { }

        public string prefix { get; private set; }

        public CryptoAPI.CryptoApiAsymmetricAlgorithm cryptoApiAsymmetricAlgorithm { set; private get; } = null;

        public new void ComputeSignature()
        {
            prefix = "";
            base.ComputeSignature();
        }
        public void ComputeSignature(string prefix)
        {
            this.prefix = prefix;

            this.BuildDigestedReferences();

            string algorithmOID = cryptoApiAsymmetricAlgorithm.GetUserKey().SignatureAlgorithm.Value;
            if (this.SignedInfo.SignatureMethod == null)
            {
                if (!OID_DEF.ContainsKey(algorithmOID))
                {
                    throw new CryptographicException("Cryptography_Xml_CreatedKeyFailed");
                }

                this.SignedInfo.SignatureMethod = OID_DEF[algorithmOID];
            }
            ((Reference)this.SignedInfo.References[0]).AddTransform(new XmlDsigC14NTransform());

            SignatureDescription description = CryptoConfig.CreateFromName(this.SignedInfo.SignatureMethod) as SignatureDescription;
            if (description == null)
            {
                throw new CryptographicException("Cryptography_Xml_SignatureDescriptionNotCreated");
            }
            HashAlgorithm hash = description.CreateDigest();
            if (hash == null)
            {
                throw new CryptographicException("Cryptography_Xml_CreateHashAlgorithmFailed");
            }

            HashAlgorithmName hashAlgorithm = HashAlgorithmName.SHA256;
            switch (algorithmOID)
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

            Signature.ObjectList.Add(hash);
            this.m_signature.SignatureValue = this.cryptoApiAsymmetricAlgorithm.SignData(this.GetC14NDigest(hash), hashAlgorithm);
        }

        public new XmlElement GetXml()
        {
            var e = base.GetXml();
            SetPrefix(prefix, e);
            return e;
        }

        private void BuildDigestedReferences()
        {
            var t = typeof(SignedXml);
            var m = t.GetMethod("BuildDigestedReferences", BindingFlags.NonPublic | BindingFlags.Instance);
            m.Invoke(this, new object[] { });
        }

        private byte[] GetC14NDigest(HashAlgorithm hash)
        {
            var document = new XmlDocument();
            document.PreserveWhitespace = true;
            var e = this.SignedInfo.GetXml();
            SetPrefix(prefix, e);
            document.AppendChild(document.ImportNode(e, true));

            var canonicalizationMethodObject = this.SignedInfo.CanonicalizationMethodObject;
            canonicalizationMethodObject.LoadInput(document);
            return canonicalizationMethodObject.GetDigestedOutput(hash);
            //var t = new StreamReader(((Stream)canonicalizationMethodObject.GetOutput())).ReadToEnd();
            //Console.WriteLine("C14Nの結果:{0}", t);
            //var x = ((MemoryStream)canonicalizationMethodObject.GetOutput()).ToArray();
            //return x;
        }

        private void SetPrefix(string prefix, XmlNode node)
        {
            foreach (XmlNode n in node.ChildNodes)
            {
                SetPrefix(prefix, n);
            }
            node.Prefix = prefix;
        }
    }
}
