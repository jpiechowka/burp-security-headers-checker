# Burp Security Headers Checker
Super simple Burp Suite extension adding passive scanner checks for missing security headers in server responses

Headers checked:
* Content-Security-Policy (CSP)
* Feature-Policy
* Strict-Transport-Security (HSTS)
* X-Frame-Options
* X-Content-Type-Options
* X-XSS-Protection
* Referrer-Policy

### Building

To build release JAR with all dependencies (by using com.github.johnrengelman.shadow Gradle plugin) execute the command below from project root directory:
```./gradlew clean shadowJar```
