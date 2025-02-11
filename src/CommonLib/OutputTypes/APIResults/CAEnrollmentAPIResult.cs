namespace SharpHoundCommonLib.OutputTypes;

public class CAEnrollmentAPIResult : APIResult{
    public CAEnrollmentEndpoint Result { get; set; }
    
    public static CAEnrollmentAPIResult Fail(string error) {
        return new CAEnrollmentAPIResult {
            Collected = false,
            FailureReason = error
        };
    }
}