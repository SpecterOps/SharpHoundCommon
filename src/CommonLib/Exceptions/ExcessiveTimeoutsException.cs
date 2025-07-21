using System;

namespace SharpHoundCommonLib.Exceptions {
    internal class ExcessiveTimeoutsException : ApplicationException {
        public ExcessiveTimeoutsException() {
        }

        public ExcessiveTimeoutsException(string message) : base(message) { }
    }
}