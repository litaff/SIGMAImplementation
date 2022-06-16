using SIGMA;

try
{
    Console.WriteLine("Run in debug? [y]");
    var debug = Console.ReadLine() == "y";
    // create new sigma actors
    var alice = new Sigma("Alice", debug);
    var bob = new Sigma("Bob", debug);

    var connectionProvider = new SigmaProvider(new List<Sigma> {alice, bob});
    if (!connectionProvider.EstablishConnection()) throw new ConnectionFailedException("Connection failed");

    var input = Helper.ReadLine();
    while (input != "q")
    {
        if(input == null) continue;
        var id = input.Split()[0];
        var elements = input.Split().Skip(1);
        var msg = string.Join(" ", elements);
        byte[] encryptedMessage;
        byte[] iv;
        switch (id)
        {
            case "alice":
                alice.SendSigmaMsg(msg, out encryptedMessage, out iv);
                Helper.Debug($"Encrypted message ({msg}): " + Helper.ByteArrayToString(encryptedMessage),debug);
                bob.ReceiveSigmaMsg(encryptedMessage, iv);
                break;
            case "bob":
                bob.SendSigmaMsg(msg, out encryptedMessage, out iv);
                Helper.Debug($"Encrypted message ({msg}): " + Helper.ByteArrayToString(encryptedMessage),debug);
                alice.ReceiveSigmaMsg(encryptedMessage, iv);
                break;
            default:
                continue;
        }

        input = Helper.ReadLine();
    }
}
catch (Exception e)
{
    Console.WriteLine(e);
}

    

        
