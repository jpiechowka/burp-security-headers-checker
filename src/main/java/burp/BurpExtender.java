package burp;

import lombok.val;

import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;


public class BurpExtender implements IBurpExtender, IScannerCheck {
    private static final String EXTENSION_NAME = "Burp Security Headers Checker";
    private static final String EXTENSION_VERSION = "1.0.0";

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
        val scanIssuesList = new ArrayList<IScanIssue>();

        val response = baseRequestResponse.getResponse();
        val responseInfo = this.burpExtensionHelpers.analyzeResponse(response);

        // Check if the response code is lower than 400 then proceed
        if (responseInfo.getStatusCode() < 400) {
            val responseHeaders = responseInfo.getHeaders();

            for (CheckedSecurityHeadersEnum headerToCheck : CheckedSecurityHeadersEnum.values()) {
                boolean containsCheckedHeader = false;

                for (String responseHeader : responseHeaders) {
                    if (responseHeader.toLowerCase().contains(headerToCheck.getHeaderName().toLowerCase())) {
                        containsCheckedHeader = true;
                        break;
                    }
                }

                if (!containsCheckedHeader) {
                    val missingHeadersSanIssue = new MissingSecurityHeaderIssue(
                            this.burpExtensionHelpers.analyzeRequest(baseRequestResponse).getUrl(),
                            "Missing Security Header: " + headerToCheck.getHeaderName(),
                            "No " + headerToCheck.getHeaderName() + " security header has been detected in the server responses.",
                            new IHttpRequestResponse[]{this.burpExtenderCallbacks.applyMarkers(baseRequestResponse, null, null)},
                            baseRequestResponse.getHttpService()
                    );

                    scanIssuesList.add(missingHeadersSanIssue);
                }

            }
            return scanIssuesList;
        } else {
            return Collections.emptyList();
        }
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

}