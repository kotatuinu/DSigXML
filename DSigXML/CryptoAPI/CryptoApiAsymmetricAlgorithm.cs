using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace CryptoAPI
{
    public class CryptoApiAsymmetricAlgorithm : AsymmetricAlgorithm, ICspAsymmetricAlgorithm
    {
        private CryptoApi.SafeCryptProvHandle _hCryptProv;
        private CryptoApi.SafeCryptKeyHandle _hUserKey;

        public CspKeyContainerInfo CspKeyContainerInfo => throw new NotImplementedException();

        public CryptoApiAsymmetricAlgorithm(string cspName, uint providerType)
        {
            // CryptAcquireContext�Ńv���o�C�_�[���擾
            _hCryptProv = CryptoApi.SafeCryptProvHandle.InvalidHandle;
            bool isSuccess = CryptoApi.CryptAcquireContext(
                ref _hCryptProv,
                null,
                cspName,
                providerType,
                0);

            if (!isSuccess)
            {
                throw new CryptographicException($"CryptAcquireContext failed. Error: {Marshal.GetLastWin32Error()}");
            }

            // CryptGetUserKey�Ń��[�U�[�L�[���擾
            _hUserKey = CryptoApi.SafeCryptKeyHandle.InvalidHandle;
            isSuccess = CryptoApi.CryptGetUserKey(
                _hCryptProv,
                CryptoApi.AT_SIGNATURE,
                ref _hUserKey);

            if (!isSuccess)
            {
                throw new CryptographicException($"CryptGetUserKey failed. Error: {Marshal.GetLastWin32Error()}");
            }
        }

        public X509Certificate2 GetUserKey()
        {

            // CryptGetKeyParam ���p�ҏؖ����T�C�Y�擾
            // hKey: ���p�Ҍ��n���h��
            // dwParam: KP_CERTIFICATE
            // pbData: NULL
            // pdwDataLen: ���p�ҏؖ������i�[�̈�A�h���X
            // dwFlags: 0
            uint dwDataLen = 0;
            bool isSuccess = CryptoApi.CryptGetKeyParam(
                    _hUserKey,
                    CryptoApi.KP_CERTIFICATE,
                    IntPtr.Zero,
                    ref dwDataLen,
                    0);
            if (!isSuccess)
            {
                var err = Marshal.GetLastWin32Error();
                Console.WriteLine("CryptGetUserKey 1 failed. err=" + err);
                return null;
            }

            // CryptGetKeyParam ���p�ҏؖ����擾
            // hKey: ���p�Ҍ��n���h��
            // dwParam: KP_CERTIFICATE
            // pbData: ���p�ҏؖ����i�[�̈�A�h���X
            // pdwDataLen: ���p�ҏؖ������i�[�̈�A�h���X
            // dwFlags: 0
            IntPtr pbDataPtr = Marshal.AllocHGlobal((int)dwDataLen);
            isSuccess = CryptoApi.CryptGetKeyParam(
                _hUserKey,
                CryptoApi.KP_CERTIFICATE,
                pbDataPtr,
                ref dwDataLen,
                0);
            if (!isSuccess)
            {
                var err = Marshal.GetLastWin32Error();
                Console.WriteLine("CryptGetUserKey 2 failed. err=" + err);
                return null;
            }

            byte[] array = new byte[dwDataLen];
            Marshal.Copy(pbDataPtr, array, 0, (int)dwDataLen);
            Marshal.FreeHGlobal(pbDataPtr);

            return new X509Certificate2(array);
        }
        public byte[] SignData(byte[] data, HashAlgorithmName hashAlgorithm)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));

            // �n�b�V���I�u�W�F�N�g���쐬
            CryptoApi.SafeCryptHashHandle hHash = CryptoApi.SafeCryptHashHandle.InvalidHandle;
            uint algId = (hashAlgorithm == HashAlgorithmName.SHA256) ? CryptoApi.CALG_SHA_256 : CryptoApi.CALG_SHA1;

            bool isSuccess = CryptoApi.CryptCreateHash(
                _hCryptProv,
                algId,
                IntPtr.Zero,
                0,
                ref hHash);

            if (!isSuccess)
            {
                throw new CryptographicException($"CryptCreateHash failed. Error: {Marshal.GetLastWin32Error()}");
            }

            try
            {
                // �f�[�^���n�b�V��
                IntPtr pbData = Marshal.AllocHGlobal(data.Length);
                Marshal.Copy(data, 0, pbData, data.Length);

                isSuccess = CryptoApi.CryptHashData(
                    hHash,
                    pbData,
                    (uint)data.Length,
                    0);

                Marshal.FreeHGlobal(pbData);

                if (!isSuccess)
                {
                    throw new CryptographicException($"CryptHashData failed. Error: {Marshal.GetLastWin32Error()}");
                }

                // �����T�C�Y���擾
                uint dwSigLen = 0;
                isSuccess = CryptoApi.CryptSignHash(
                    hHash,
                    CryptoApi.AT_SIGNATURE,
                    null,
                    0,
                    IntPtr.Zero,
                    ref dwSigLen);

                if (!isSuccess)
                {
                    throw new CryptographicException($"CryptSignHash (size) failed. Error: {Marshal.GetLastWin32Error()}");
                }

                // �����𐶐�
                IntPtr pbSignature = Marshal.AllocHGlobal((int)dwSigLen);
                isSuccess = CryptoApi.CryptSignHash(
                    hHash,
                    CryptoApi.AT_SIGNATURE,
                    null,
                    0,
                    pbSignature,
                    ref dwSigLen);

                if (!isSuccess)
                {
                    throw new CryptographicException($"CryptSignHash failed. Error: {Marshal.GetLastWin32Error()}");
                }

                byte[] signature = new byte[dwSigLen];
                Marshal.Copy(pbSignature, signature, 0, (int)dwSigLen);
                Marshal.FreeHGlobal(pbSignature);

                return signature;
            }
            finally
            {
                hHash.Dispose();
            }
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _hUserKey?.Dispose();
                _hCryptProv?.Dispose();
            }
            base.Dispose(disposing);
        }

        public override void FromXmlString(string xmlString)
        {
            throw new NotImplementedException();
        }

        public override string ToXmlString(bool includePrivateParameters)
        {
            throw new NotImplementedException();
        }

        public byte[] ExportCspBlob(bool includePrivateParameters)
        {
            throw new NotImplementedException();
        }

        public void ImportCspBlob(byte[] rawData)
        {
            throw new NotImplementedException();
        }
    }
}