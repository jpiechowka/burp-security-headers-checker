package burp;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Getter
public enum CheckedSecurityHeadersEnum {
    CSP("Content-Security-Policy"),
    FEATURE_POLICY("Feature-Policy"),
    HSTS("Strict-Transport-Security"),
    X_FRAME_OPTIONS("X-Frame-Options"),
    X_CONTENT_TYPE("X-Content-Type-Options"),
    X_XSS("X-XSS-Protection"),
    REFERRER_POLICY("Referrer-Policy");

    private final String headerName;
}
