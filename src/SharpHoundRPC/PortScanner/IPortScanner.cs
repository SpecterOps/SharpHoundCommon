using System.Threading.Tasks;

namespace SharpHoundRPC.PortScanner;

public interface IPortScanner
{
    Task<bool> CheckPort(string hostname, int port, bool throwError = false);
}