
public struct Point
{
    public int x, y;

    public Point(int p1, int p2)
    {
        x = p1;
        y = p2;
    }

    public override string ToString()
    {
        return "[x = " + x + ", y = " + y + "]";
    }
}

public class CSTest
{
    //private static Point localPoint;

    /*
    public static double avg(double[] items)
    {
        double sum = 0;
        for(int i = 0; i < items.Length; i++)
        {
            sum += items[i];
        }
        return sum;
    }
    */

    public static void BadSwapPoint(Point p)
    {
        var tmp = p.x;
        p.x = p.y;
        p.y = tmp;
    }

    public static void GoodSwapPoint(ref Point p)
    {
        var tmp = p.x;
        p.x = p.y;
        p.y = tmp;
    }

    static void Main(string[] args)
    {
        var p = new Point(3, 5);
        System.Console.WriteLine("original point: " + p.ToString());
        BadSwapPoint(p);
        System.Console.WriteLine("after bad swap: " + p.ToString());
        GoodSwapPoint(ref p);
        System.Console.WriteLine("after good swap: " + p.ToString());
        //GoodSwapPoint(ref localPoint);
    }
}

