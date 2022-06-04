namespace SIGMA;

/// <summary>
/// Establishes a connection between two sigma actors (A, B) in three steps:<para />
/// 1. A sends it's public key to B.<para />
/// 2. B sends it's public key, identity, both public keys signed (with a separate algorithm) and
/// signed identity with a mac function to A, who then checks signed keys and identity.<para />
/// 3. A sends it's identity, both public keys signed (with a separate algorithm) and
/// signed identity with a mac function to B, who then checks signed keys and identity.<para />
/// After all that session keys are derived.
/// </summary>
public class SigmaProvider
{
    private readonly Sigma _a;
    private readonly Sigma _b;
    
    /// <param name="actors"> Only two first actors are used </param>
    public SigmaProvider(IReadOnlyList<Sigma> actors)
    {
        // if these sigma actors are not overriden,
        // then the provider becomes invalid and return while establishing connection
        _a = new Sigma("null");
        _b = new Sigma("null");
        if (actors.Count < 2) return;
        
        _a = actors[0];
        _b = actors[1];
    }

    /// <returns> True if connection was successful </returns>
    public bool EstablishConnection()
    {
        if (!ValidateProvider()) return false;
        FirstStep();
        if (!SecondStep()) return false;
        if (!ThirdStep()) return false;
        SetSessionKeys();
        return true;
    }

    /// <returns> True if provider was initialized correctly </returns>
    private bool ValidateProvider()
    {
        return _a.Identity != "null" && _b.Identity != "null";
    }
    
    private void FirstStep()
    {
        Console.WriteLine("First step");
        _b.SetPartnerPublicKey(_a.GetDhPublicKey);
    }

    private bool SecondStep()
    {
        Console.WriteLine("Second step");
        _a.SetPartnerPublicKey(_b.GetDhPublicKey);
        _a.SetPartnerIdentity(_b.Identity);
        if (_a.CheckSignedPublicKeys(_b.GetSignedKeys(), _b.GetRsaParameters()))
        {
            if (_a.VerifyMac(_b.SignMac(_b.Identity))) 
                return true;
            Console.WriteLine("Partner identity sent to A was tampered with");
            return false;
        }
        Console.WriteLine("Public keys sent to A failed to verify");
        return false;
    }

    private bool ThirdStep()
    {
        Console.WriteLine("Third step");
        _b.SetPartnerIdentity(_a.Identity);
        if (_b.CheckSignedPublicKeys(_a.GetSignedKeys(), _a.GetRsaParameters()))
        {
            if (_b.VerifyMac(_a.SignMac(_a.Identity))) 
                return true;
            Console.WriteLine("Partner identity sent to B was tampered with");
            return false;
        }
        Console.WriteLine("Public keys sent to B failed to verify");
        return false;
    }

    private void SetSessionKeys()
    {
        Console.WriteLine("Key derivation");
        _a.DeriveSessionKey();
        _b.DeriveSessionKey();
    }

}