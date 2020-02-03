package burp;

import lombok.val;

import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;


public class BurpExtender implements IBurpExtender, IScannerCheck {
    private static final String EXTENSION_NAME = "Burp Security Headers Checker";
    private static final String EXTENSION_VERSION = "1.1.0";

    private IBurpExtenderCallbacks burpExtenderCallbacks;
    private IExtensionHelpers burpExtensionHelpers;


    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
        this.burpExtenderCallbacks = callbacks;
        this.burpExtensionHelpers = callbacks.getHelpers();

        callbacks.setExtensionName(EXTENSION_NAME);
        callbacks.registerScannerCheck(this);

        PrintWriter stdout = new PrintWriter(callbacks.getStdout(), true);
        stdout.println(EXTENSION_NAME + " version: " + EXTENSION_VERSION + " has been loaded");
    }


    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        return checkResponseSecurityHeaders(baseRequestResponse);
    }


    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        return Collections.emptyList();
    }


    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        if (existingIssue.getIssueName().equalsIgnoreCase(newIssue.getIssueName()))
            return -1; // Return old issue
        else return 0;
    }


    private List<IScanIssue> checkResponseSecurityHeaders(IHttpRequestResponse baseRequestResponse) {
        val response = baseRequestResponse.getResponse();
        val responseInfo = this.burpExtensionHelpers.analyzeResponse(response);

        val scanIssuesList = new ArrayList<IScanIssue>();

        for (CheckedSecurityHeadersEnum headerToCheck : CheckedSecurityHeadersEnum.values()) {
            boolean containsCheckedHeader = false;

            for (String responseHeader : responseInfo.getHeaders()) {
                if (responseHeader.toLowerCase().contains(headerToCheck.getHeaderName().toLowerCase())) {
                    containsCheckedHeader = true;
                    break;
                }
            }

            if (!containsCheckedHeader) {
                val missingHeadersScanIssue = createNewScannerIssue(responseInfo.getStatusCode(), headerToCheck, baseRequestResponse);
                scanIssuesList.add(missingHeadersScanIssue);
            }
        }

        return scanIssuesList;
    }


    private MissingSecurityHeaderIssue createNewScannerIssue(int statusCode, CheckedSecurityHeadersEnum headerToCheck, IHttpRequestResponse baseRequestResponse) {
        String issueName = "";

        if (statusCode < 400) {
            issueName = "Missing Security Header: " + headerToCheck.getHeaderName();
        }

        if (statusCode >= 400 && statusCode < 500) {
            issueName = "Missing Security Header in 4XX response: " + headerToCheck.getHeaderName();
        }

        if (statusCode == 500) {
            issueName = "Missing Security Header in 500 response: " + headerToCheck.getHeaderName();
        }

        if (statusCode > 500) {
            issueName = "Missing Security Header in other response: " + headerToCheck.getHeaderName();
        }

        return new MissingSecurityHeaderIssue(
                this.burpExtensionHelpers.analyzeRequest(baseRequestResponse).getUrl(),
                issueName,
                "No " + headerToCheck.getHeaderName() + " security header has been detected in the server responses.",
                new IHttpRequestResponse[]{this.burpExtenderCallbacks.applyMarkers(baseRequestResponse, null, null)},
                baseRequestResponse.getHttpService()
        );
    }

}
