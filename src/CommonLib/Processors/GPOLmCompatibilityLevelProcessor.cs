using System;
using System.DirectoryServices.Protocols;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using SharpHoundCommonLib.LDAPQueries;

namespace SharpHoundCommonLib.Processors
{
    public class GPOLmCompatibilityLevelProcessor
    {
        private static readonly Regex NTLMv1Regex = new Regex(@"\\LmCompatibilityLevel *= *\d+ *, *(\d)", RegexOptions.Compiled | RegexOptions.Singleline | RegexOptions.IgnoreCase);

        private readonly ILogger _log;

        private readonly ILDAPUtils _utils;

        public GPOLmCompatibilityLevelProcessor(ILDAPUtils utils, ILogger log = null)
        {
            _utils = utils;
            _log = log ?? Logging.LogProvider.CreateLogger("GPOLmCompatProc");
        }

        public Task<Boolean> ReadGPOLmCompatibilityLevel(ISearchResultEntry entry)
        {
            var dn = entry.DistinguishedName;
            return ReadGPOLmCompatibilityLevel(dn);
        }

        public async Task<Boolean> ReadGPOLmCompatibilityLevel(string gpDn)
        {
            var opts = new LDAPQueryOptions
            {
                Filter = new LDAPFilter().AddAllObjects().GetFilter(),
                Scope = SearchScope.Base,
                Properties = CommonProperties.GPCFileSysPath,
                AdsPath = gpDn
            };
            var filePath = _utils.QueryLDAP(opts).FirstOrDefault()?
                .GetProperty(LDAPProperties.GPCFileSYSPath);
            if (filePath == null)
            {
                _log.LogWarning("Unable to process {} for NTLMv1 flag", gpDn);
                return false;
            }

            return await ProcessGPOTemplateFile(filePath);
        }

        /// <summary>
        ///     Parses a GPO GptTmpl.inf file and grep lmcompatibilitylevel value
        /// </summary>
        /// <param name="basePath"></param>
        /// <returns>
        ///     lmcompatibilitylevel < 3
        /// </returns>
        internal async Task<Boolean> ProcessGPOTemplateFile(string basePath)
        {
            var templatePath = Path.Combine(basePath, "MACHINE", "Microsoft", "Windows NT", "SecEdit", "GptTmpl.inf");

            if (!File.Exists(templatePath))
                return false;

            FileStream fs;
            try
            {
                fs = new FileStream(templatePath, FileMode.Open, FileAccess.Read);
            }
            catch
            {
                return false;
            }

            using var reader = new StreamReader(fs);
            var content = await reader.ReadToEndAsync();
            var ntlmv1Match = NTLMv1Regex.Match(content);

            if (!ntlmv1Match.Success)
                return false;

            //We've got a match! Lets figure out whats going on
            var ntlmv1Text = int.Parse(ntlmv1Match.Groups[1].Value);
            return ntlmv1Text < 3;
        }
    }
}