# DSigXML
PKCS#12を使ったXML署名の署名付与・署名検証のテストプログラム

Usage：
・署名付与：P12ファイル使用
DSigXML.exe -s test.xml -f my-identity.p12 -p 1234 -id xxx -o outputP12.xml

・署名付与：ICカード（以下の例はマイナンバーカード 利用者証明用電子証明書）
DSigXML.exe -s test.xml -pr "JPKI Crypto Service Provider for Auth" -id xxx -o outputICAuth.xml
	※：CSP名は以下のレジストリ配下のパスを参照
		64bitアプリ：コンピューター\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\Defaults\Provider
		32bitアプリ：コンピューター\HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Cryptography\Defaults\Provider

・署名検証
DSigXML.exe -v outputICAuth.xml

・動作検証：署名付きXMLの証明書情報取得
DSigXML.exe -ix outputICAuth.xml

・動作検証：電子証明書ファイル証明書情報取得
DSigXML.exe -if my-identity.p12 -p 1234

・動作検証：ICカード証明書情報取得
DSigXML.exe -ii "JPKI Crypto Service Provider for Auth"

・動作検証：ダイジェスト値生成
DSigXML.exe -d test.xml -dg SHA256 -c DSIGC14 -id xxx
