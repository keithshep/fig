public class CSTest
{
    public static double avg(double[] items)
    {
        double sum = 0;
        for(int i = 0; i < items.Length; i++)
        {
            sum += items[i];
        }
        return sum;
    }
}

