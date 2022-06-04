using System.Security.Cryptography;
using System.Text;

namespace SIGMA;
// Added only to suppress warning about ECDiffieHellmanCng platform support
#pragma warning disable CA1416
public class Sigma
{
    public readonly string Identity;
    private byte[] _sessionKey;
    private SigmaPartner _partner;
    private readonly bool _debug;

    public Sigma(string id, bool debug = false)
    {
        Identity = id;
        _debug = debug;
        _sessionKey = Array.Empty<byte>();
        _rsa = new RSACryptoServiceProvider();
        _diffieHellman = new ECDiffieHellmanCng
        {
            KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hmac,
            HashAlgorithm = CngAlgorithm.Sha256
        };
    }

    #region DH

        private readonly ECDiffieHellmanCng _diffieHellman;
        public byte[] GetDhPublicKey => _diffieHellman.PublicKey.ToByteArray();

        /// <returns>
        /// Returns two signed public keys, where the first is this objects and second its partners
        /// </returns>
        public List<byte[]> GetSignedKeys()
        {
            var result = new List<byte[]>();
            var myExponentToSign = GetDhPublicKey;
            var partnersExponentToSign = _partner.PublicKey;
            result.Add(HashAndSignBytes(myExponentToSign));
            result.Add(HashAndSignBytes(partnersExponentToSign));
            return result;
        }

        /// <param name="signedKeys">
        /// First key should be partners to this object, second should be this objects
        /// </param>
        /// <param name="signer"> RSA parameters of the signer </param>
        /// <returns> True if public keys match </returns>
        public bool CheckSignedPublicKeys(List<byte[]>  signedKeys, RSAParameters signer)
        {
            var myPublicKeyToVerify = GetDhPublicKey;
            var partnersPublicKeyToVerify = _partner.PublicKey;
            var result = 
                VerifySignedHash(partnersPublicKeyToVerify, signedKeys[0], signer) && 
                VerifySignedHash(myPublicKeyToVerify, signedKeys[1], signer);
            Console.WriteLine($"{Identity}: Signed keys correct: {result}");
            return result;
        }
    #endregion
    
    #region RSA

        private readonly RSACryptoServiceProvider _rsa;

        public RSAParameters GetRsaParameters()
        {
            return _rsa.ExportParameters(false);
        }

        // may be used later when establishing a connection
        public byte[] RsaDecrypt(byte[] dataToDecrypt, bool doOaepPadding)
        {
            var decryptedData = _rsa.Decrypt(dataToDecrypt, doOaepPadding);
            return decryptedData;
        }
        
        // may be used later when establishing a connection
        public static byte[] RsaEncrypt(byte[] dataToEncrypt, RSAParameters rsaKeyInfo, bool doOaepPadding)
        {
            using var rsa = new RSACryptoServiceProvider();
            rsa.ImportParameters(rsaKeyInfo);
            var encryptedData = rsa.Encrypt(dataToEncrypt, doOaepPadding);
            return encryptedData;
        }

        private byte[] HashAndSignBytes(byte[] dataToSign)
        {
            try
            {
                return _rsa.SignData(dataToSign, SHA256.Create());
            }
            catch(CryptographicException e)
            {
                Console.WriteLine(e.Message);

                return null!;
            }
        }

        private static bool VerifySignedHash(byte[] dataToVerify, byte[] signedData, RSAParameters key)
        {
            try
            {
                using var rsa = new RSACryptoServiceProvider();

                rsa.ImportParameters(key);
                
                return rsa.VerifyData(dataToVerify, SHA256.Create(), signedData);
            }
            catch(CryptographicException e)
            {
                Console.WriteLine(e.Message);

                return false;
            }
        }
        
    #endregion

    #region HMAC

        private byte[] MacKey()
        {
            _diffieHellman.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hmac;
            var derivedKey = _diffieHellman.DeriveKeyMaterial(CngKey.Import(_partner.PublicKey, CngKeyBlobFormat.EccPublicBlob));
            Helper.Debug($"{Identity}: MacKey: {Helper.ByteArrayToString(derivedKey)}", _debug);
            return derivedKey;
        }
    
        public byte[] SignMac(string msg)
        {
            var byteConverter = new UTF8Encoding();
            var msgToSign = byteConverter.GetBytes(msg);
            using var hmac = new HMACSHA256(MacKey());
            return hmac.ComputeHash(msgToSign);
        }
        
        /// <returns> True if maced _partner.Identity is the same as signedMsg</returns>
        public bool VerifyMac(byte[] signedMsg)
        {
            var byteConverter = new UTF8Encoding();
            var msgToVerify = byteConverter.GetBytes(_partner.Identity);
            var error = false;
            // Initialize the keyed hash object.
            using (var hmac = new HMACSHA256(MacKey()))
            {

                var computedHash = hmac.ComputeHash(msgToVerify);
                // compare the computed hash with the stored value

                for (var i = 0; i < signedMsg.Length; i++)
                {
                    if (computedHash[i] != signedMsg[i])
                    {
                        error = true;
                    }
                }
            }
            Console.WriteLine($"{Identity}: Partner identity verified: {!error}");
            return !error;
        
        } //end VerifyFile

    #endregion

    #region SIGMA

        public void SendSigmaMsg(string secretMessage, out byte[] encryptedMessage, out byte[] iv)
        {
            using var aes = Aes.Create();
            aes.Key = _sessionKey;
            iv = aes.IV;

            // Encrypt the message
            using var ciphertext = new MemoryStream();
            using var cs = new CryptoStream(ciphertext, aes.CreateEncryptor(), CryptoStreamMode.Write);
            var plaintextMessage = Encoding.UTF8.GetBytes(secretMessage);
            cs.Write(plaintextMessage, 0, plaintextMessage.Length);
            cs.Close();
            encryptedMessage = ciphertext.ToArray();
        }
        
        public void ReceiveSigmaMsg(byte[] encryptedMessage, byte[] iv)
        {
            using var aes = Aes.Create();
            aes.Key = _sessionKey;
            aes.IV = iv;
            // Decrypt the message
            using var plaintext = new MemoryStream();
            using var cs = new CryptoStream(plaintext, aes.CreateDecryptor(), CryptoStreamMode.Write);
            cs.Write(encryptedMessage, 0, encryptedMessage.Length);
            cs.Close();
            var message = Encoding.UTF8.GetString(plaintext.ToArray());
            Console.WriteLine($"To {Identity}: {message}");
        }
        
        public void DeriveSessionKey()
        {
            Console.WriteLine($"{Identity}: Deriving a session key");
            _diffieHellman.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash;
            _sessionKey = _diffieHellman.DeriveKeyMaterial(CngKey.Import(_partner.PublicKey, CngKeyBlobFormat.EccPublicBlob));
            Helper.Debug($"{Identity}: _sessionKey = {Helper.ByteArrayToString(_sessionKey)}",_debug);
        }

    #endregion
    
   
    public void SetPartnerPublicKey(byte[] pk)
    {
        _partner.PublicKey = pk;
        Console.WriteLine($"{Identity}: Setting partner public key");
        Helper.Debug($"{Identity}: _partner.PublicKey: {Helper.ByteArrayToString(_partner.PublicKey)}", _debug);
    }
    
    public void SetPartnerIdentity(string identity)
    {
        _partner.Identity = identity;
        Console.WriteLine($"{Identity}: Setting partner identity");
        Helper.Debug($"{Identity}: _partner.Identity: {_partner.Identity}", _debug);
    }
    
    private struct SigmaPartner
    {
        public byte[] PublicKey;
        public string Identity;
    }
    
#pragma warning restore CA1416
}