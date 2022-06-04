namespace SIGMA;

public class ConnectionFailedException : Exception
{
    public ConnectionFailedException()
    {
        
    }

    public ConnectionFailedException(string msg)
        : base(msg)
    {
        
    }

    public ConnectionFailedException(string msg, Exception inner)
        : base(msg, inner)
    {
        
    }
}