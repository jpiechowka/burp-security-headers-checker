package burp;

import lombok.Data;

@Data
class MissingSecurityHeaderIssue implements IScanIssue {

    private static final int ISSUE_TYPE = 0;
    private static final String SEVERITY = "Low";
    private static final String CONFIDENCE = "Certain";
    private static final String ISSUE_BACKGROUND = null;
    private static final String REMEDIATION_BACKGROUND = null;
    private static final String REMEDIATION_DETAIL = "It is recommended to implement the security header mentioned in the issue details / issue name";

    private final java.net.URL url;
    private final String issueName;
    private final String issueDetail;
    private final IHttpRequestResponse[] httpMessages;
    private final IHttpService httpService;


    @Override
    public int getIssueType() {
        return ISSUE_TYPE;
    }

    @Override
    public String getSeverity() {
        return SEVERITY;
    }

    @Override
    public String getConfidence() {
        return CONFIDENCE;
    }

    @Override
    public String getIssueBackground() {
        return ISSUE_BACKGROUND;
    }

    @Override
    public String getRemediationBackground() {
        return REMEDIATION_BACKGROUND;
    }

    @Override
    public String getRemediationDetail() {
        return REMEDIATION_DETAIL;
    }
}