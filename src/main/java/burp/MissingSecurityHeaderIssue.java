package burp;

import lombok.Data;

@Data
class MissingSecurityHeaderIssue implements IScanIssue {

    private static final int ISSUE_TYPE = 0;
    private static final String SEVERITY = "Low";
    private static final String CONFIDENCE = "Certain";
    private static final String ISSUE_BACKGROUND = null;
    private static final String REMEDIATION_BACKGROUND = null;
    private static final String REMEDIATION_DETAIL = "It is recommended to implement the security header mentioned in the issue details / issue name. " +
            "More information can be found by visiting the following URLs:\n\n" +
            "<ul><li><a href=https://securityheaders.com>Security Headers</a></li>" +
            "<li><a href=https://www.owasp.org/index.php/OWASP_Secure_Headers_Project#tab=Headers>OWASP Secure Headers Project</a></li>" +
            "<li><a href=https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html>OWASP REST Security Cheat Sheet</a></li>" +
            "<li><a href=https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html>OWASP CSP Cheat Sheet</a></li>" +
            "<li><a href=https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html>OWASP HSTS Cheat Sheet</a></li>" +
            "<li><a href=https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html>OWASP Clickjacking Defense Cheat Sheet</a></li></ul>";

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