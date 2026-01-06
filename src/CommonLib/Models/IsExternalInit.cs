using System.ComponentModel;

// This class while it looks unused, is used to be able to build the records for a .Net Framework Target. 
// see: https://stackoverflow.com/questions/64749385/predefined-type-system-runtime-compilerservices-isexternalinit-is-not-defined
// see: https://developercommunity.visualstudio.com/t/error-cs0518-predefined-type-systemruntimecompiler/1244809

namespace System.Runtime.CompilerServices
{
    [EditorBrowsable(EditorBrowsableState.Never)]
    internal class IsExternalInit{}
}