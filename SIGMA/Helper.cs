namespace SIGMA;

public static class Helper
{
    public static string ByteArrayToString(byte[] bytes)
    {
        return bytes.Length < 1 ? "" : bytes.Aggregate("", (current, b) => current + (b + " "));
    }

    public static void Debug(string msg, bool debug)
    {
        if(!debug) return;
        Console.WriteLine($"Debug# {msg}");
    }
    
    private static void DeletePrevConsoleLine()
    {
        if (Console.CursorTop == 0) return;
        Console.SetCursorPosition(0, Console.CursorTop - 1);
        Console.Write(new string(' ', Console.WindowWidth));
        Console.SetCursorPosition(0, Console.CursorTop - 1);
    }

    public static string? ReadLine()
    {
        var input = Console.ReadLine();
        DeletePrevConsoleLine();
        return input;
    }
}