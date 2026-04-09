namespace SharpHoundCommonLib
{
    public class LDAPConnectionCacheKey
    {
        public bool GlobalCatalog { get; }
        public string Domain { get; }
        public string Server { get; set; }

        public LDAPConnectionCacheKey(string domain, bool globalCatalog)
        {
            GlobalCatalog = globalCatalog;
            Domain = domain;
        }

        protected bool Equals(LDAPConnectionCacheKey other)
        {
            return GlobalCatalog == other.GlobalCatalog && Domain == other.Domain;
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != this.GetType()) return false;
            return Equals((LDAPConnectionCacheKey)obj);
        }

        public override int GetHashCode()
        {
            unchecked
            {
                return (GlobalCatalog.GetHashCode() * 397) ^ (Domain != null ? Domain.GetHashCode() : 0);
            }
        }
    }
}