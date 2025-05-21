using Microsoft.Win32.SafeHandles;
using System;
using System.Runtime.InteropServices;
using System.Security;

namespace CryptoAPI
{
    class CryptoApi
    {
        internal const String ADVAPI32 = "advapi32.dll";
        internal const String CRYPT32 = "crypt32.dll";
        internal const String KERNEL32 = "kernel32.dll";
        internal const uint AT_SIGNATURE = 2;
        internal const uint KP_CERTIFICATE = 26;
        internal const uint CALG_SHA1 = (4 << 13) + 4;
        internal const uint CALG_SHA_256 = (4 << 13) + 12;

        [DllImport(ADVAPI32, CharSet = CharSet.Ansi, BestFitMapping = false, EntryPoint = "CryptAcquireContextA")]
        public static extern
        bool CryptAcquireContext(
            [In, Out] ref SafeCryptProvHandle hCryptProv,
            [In][MarshalAs(UnmanagedType.LPStr)] string pszContainer,
            [In][MarshalAs(UnmanagedType.LPStr)] string pszProvider,
            [In] uint dwProvType,
            [In] uint dwFlags);

        [DllImport(ADVAPI32, SetLastError = true)]
        public static extern
        bool CryptReleaseContext(
            [In, Out] ref SafeCryptProvHandle hCryptProv,
            [In] uint dwFlags);

        // CryptGetUserKey 利用者鍵ハンドル取得
        // hProv: CryptAcquireContext で取得したハンドル
        // dwKeySpec: AT_SIGNATURE
        // phUserKey: 利用者鍵ハンドル格納領域アドレス
        [DllImport(ADVAPI32, SetLastError = true)]
        public static extern
        bool CryptGetUserKey(
            [In] SafeCryptProvHandle hCryptProv,
            [In] uint dwKeySpec,
            [In, Out] ref SafeCryptKeyHandle phUserKey);

        // CryptGetKeyParam 利用者証明書サイズ取得
        // hKey: 利用者鍵ハンドル
        // dwParam: KP_CERTIFICATE
        // pbData: NULL
        // pdwDataLen: 利用者証明書長格納領域アドレス
        // dwFlags: 0
        [DllImport(ADVAPI32, SetLastError = true)]
        public static extern
        bool CryptGetKeyParam(
            [In] SafeCryptKeyHandle hKey,
            [In] uint dwParam,
            [In, Out] IntPtr pbData,
            [In, Out] ref uint pdwDataLen,
            [In] uint dwFlags);

        // CryptDestroyKey 利用者鍵ハンドル破棄
        // hKey: 利用者鍵ハンドル
        [DllImport(ADVAPI32, SetLastError = true)]
        public static extern
        bool CryptDestroyKey(
            [In] IntPtr hKey);

        // CryptCreateHash ハッシュオブジェクト生成
        // hProv: CryptAcquireContext で取得したハンドル
        // ALG_ID: ア ル ゴ リ ズ ム ID(CALG_SHA1 または CALG_SHA_256 のいずれかを署名方式に合わせて指定)
        // hKey: 0
        // dwFlags: 0
        // phHash: ハッシュオブジェクトのハンドル格納領域アドレス
        [DllImport(ADVAPI32, SetLastError = true)]
        public static extern
            bool CryptCreateHash(
            [In] SafeCryptProvHandle hCryptProv,
            [In] uint Algid,
            [In] IntPtr hKey,
            [In] uint dwFlags,
            [In, Out] ref SafeCryptHashHandle phHash);


        // CryptHashData ハッシュ値計算
        // hHash: ハッシュオブジェクトのハンドル
        // pbData: 署名対象データ
        // dwDataLen: 署名対象データ長
        // dwFlags: 0
        [DllImport(ADVAPI32, SetLastError = true)]
        public static extern
            bool CryptHashData(
            [In] SafeCryptHashHandle hHash,
            [In] IntPtr pbData,
            [In] uint dwDataLen,
            [In] uint dwFlags);

        // CryptGetHashParam ハッシュ値取得
        // hHash: ハッシュオブジェクトのハンドル
        // dwParam: HP_HASHVAL
        // pbData: ハッシュデータ格納領域アドレス
        // pdwDataLen: ハッシュデータ長格納領域アドレス
        // dwFlags: 0
        [DllImport(ADVAPI32, SetLastError = true)]
        public static extern
                bool CryptGetHashParam(
                [In] SafeCryptHashHandle hHash,
                [In] uint dwParam,
                [In, Out] IntPtr pbData,
                [In, Out] ref uint pdwDataLen,
                [In] uint dwFlags);

        // CryptSignHash 署名値長取得
        // hHash: 署名対象ハッシュオブジェクトのハンドル
        // dwKeySpec: AT_SIGNATURE
        // sDescription: NULL
        // dwFlags: 0
        // pbSignature: NULL
        // pdwSigLen: 署名データ長格納領域アドレス
        [DllImport(ADVAPI32, SetLastError = true)]
        public static extern
            bool CryptSignHash(
            [In] SafeCryptHashHandle hHash,
            [In] uint dwKeySpec,
            [In] string sDescription,
            [In] uint dwFlags,
            [In, Out] IntPtr pbSignature,
            [In, Out] ref uint pdwSigLen);

        // CryptDestroyHash ハッシュオブジェクト破棄
        // hHash: 破棄するハッシュオブジェクトハンドル
        [DllImport(ADVAPI32, SetLastError = true)]
        public static extern
            bool CryptDestroyHash(
            [In] SafeCryptHashHandle hHash);



        public sealed class SafeCryptProvHandle : SafeHandleZeroOrMinusOneIsInvalid
        {
            private SafeCryptProvHandle() : base(true) { }

            // 0 is an Invalid Handle  
            internal SafeCryptProvHandle(IntPtr handle) : base(true)
            {
                SetHandle(handle);
            }

            internal static SafeCryptProvHandle InvalidHandle
            {
                get { return new SafeCryptProvHandle(IntPtr.Zero); }
            }

            [DllImport(ADVAPI32, SetLastError = true),
             SuppressUnmanagedCodeSecurity]
            private static extern bool CryptReleaseContext(IntPtr hCryptProv, uint dwFlags);

            override protected bool ReleaseHandle()
            {
                return CryptReleaseContext(handle, 0);
            }
        }

        public sealed class SafeCryptKeyHandle : SafeHandleZeroOrMinusOneIsInvalid
        {
            private SafeCryptKeyHandle() : base(true) { }

            // 0 is an Invalid Handle  
            internal SafeCryptKeyHandle(IntPtr handle) : base(true)
            {
                SetHandle(handle);
            }

            internal static SafeCryptKeyHandle InvalidHandle
            {
                get { return new SafeCryptKeyHandle(IntPtr.Zero); }
            }

            [DllImport(ADVAPI32, SetLastError = true), SuppressUnmanagedCodeSecurity]
            private static extern bool CryptDestroyKey([In] IntPtr hKey);

            override protected bool ReleaseHandle()
            {
                return CryptDestroyKey(handle);
            }
        }

        internal sealed class SafeCryptHashHandle : SafeHandleZeroOrMinusOneIsInvalid
        {
            private SafeCryptHashHandle() : base(true) { }

            // 0 is an Invalid Handle  
            internal SafeCryptHashHandle(IntPtr handle) : base(true)
            {
                SetHandle(handle);
            }

            internal static SafeCryptHashHandle InvalidHandle
            {
                get { return new SafeCryptHashHandle(IntPtr.Zero); }
            }

            [DllImport(ADVAPI32, SetLastError = true), SuppressUnmanagedCodeSecurity]
            private static extern bool CryptDestroyHash([In] IntPtr hHash);

            override protected bool ReleaseHandle()
            {
                return CryptDestroyHash(handle);
            }
        }

    }
}
