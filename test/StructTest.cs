
public struct Point
{
    public double x, y, z;

    public Point(double p1, double p2, double p3)
    {
        x = p1;
        y = p2;
        z = p3;
    }
	
	public double DistSq()
	{
		return x * x + y * y + z * z;
	}

    //public override string ToString()
    //{
    //    return "[x=" + x + ", y=" + y + ", z=" + z +"]";
    //}
}

public class StructTest
{
    public static double PointDistSq(Point p)
    {
        return p.x * p.x + p.y * p.y + p.z * p.z;
    }
    
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

    /*static void Main(string[] args)
    {
    }*/
}

