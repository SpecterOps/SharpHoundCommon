using System.Threading.Tasks;

namespace SharpHoundRPC.PortScanner {
    public interface IPortScanner {
        Task<bool> CheckPort(string hostname, int port = 445, int timeout = 10000, bool throwError = false);
    }
}