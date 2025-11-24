package pascal.taie.analysis.gadget.sink;

import pascal.taie.analysis.gadget.SinkType;
import pascal.taie.ir.exp.Var;
import pascal.taie.ir.stmt.Invoke;

import java.util.Set;

/**
 * Detects Server-Side Request Forgery (SSRF) sinks.
 *
 * SSRF occurs when an attacker can cause a server to make requests
 * to arbitrary destinations, potentially accessing internal resources.
 *
 * Dangerous methods from priori-knowledge.yml:
 * - java.net.URL.openConnection() - Opens connection to attacker-controlled URL
 * - java.sql.DriverManager.getConnection(String) - JDBC URL can trigger SSRF
 *
 * References:
 * - OWASP SSRF: https://owasp.org/www-community/attacks/Server_Side_Request_Forgery
 * - JDBC SSRF: https://mogwailabs.de/en/blog/2019/04/attacking-java-rmi-via-ssrf/
 */
public class SSRFSinkRule extends AbstractSinkRule {

    public SSRFSinkRule() {
        super(SinkType.SSRF);
    }

    @Override
    public void initialize() {
        // From priori-knowledge.yml:
        // - { method: "<java.net.URL: java.net.URLConnection openConnection()>", index: [ base ], type: "SSRF" }
        // URL methods - use subclass finding to catch all implementations
        addAllSubclassSignatures("<java.net.URL: java.net.URLConnection openConnection()>");
        addAllSubclassSignatures("<java.net.URL: java.net.URLConnection openConnection(java.net.Proxy)>");
        addAllSubclassSignatures("<java.net.URL: java.io.InputStream openStream()>");
        addAllSubclassSignatures("<java.net.URL: java.lang.Object getContent()>");

        // From priori-knowledge.yml:
        // - { method: "<java.sql.DriverManager: java.sql.Connection getConnection(java.lang.String,java.util.Properties,java.lang.Class)>", index: [ 0 ], type: "SSRF" }
        // DriverManager methods - use subclass finding
        addAllSubclassSignatures("<java.sql.DriverManager: java.sql.Connection getConnection(java.lang.String)>");
        addAllSubclassSignatures("<java.sql.DriverManager: java.sql.Connection getConnection(java.lang.String,java.util.Properties)>");
        addAllSubclassSignatures("<java.sql.DriverManager: java.sql.Connection getConnection(java.lang.String,java.lang.String,java.lang.String)>");
        addAllSubclassSignatures("<java.sql.DriverManager: java.sql.Connection getConnection(java.lang.String,java.util.Properties,java.lang.Class)>");

        // Additional common SSRF vectors
        addAllSubclassSignatures("<java.net.HttpURLConnection: void connect()>");
        addAllSubclassSignatures("<java.net.URLConnection: void connect()>");
        addAllSubclassSignatures("<java.net.URLConnection: java.io.InputStream getInputStream()>");
        addAllSubclassSignatures("<java.net.URLConnection: java.io.OutputStream getOutputStream()>");
    }

    @Override
    protected boolean checkTaintedArguments(Invoke invoke, Set<Var> taintedVars) {
        String methodSig = invoke.getInvokeExp().getMethodRef().resolve().getSignature();

        // For URL.openConnection(), check if receiver (the URL object) is tainted
        // index: [base] means the receiver object
        if (methodSig.contains("java.net.URL:")) {
            return isReceiverTainted(invoke, taintedVars);
        }

        // For DriverManager.getConnection, check if the first argument (URL string) is tainted
        // index: [0] means the first parameter
        if (methodSig.contains("java.sql.DriverManager: java.sql.Connection getConnection")) {
            return isArgumentTainted(invoke, 0, taintedVars);
        }

        // For HttpURLConnection.connect(), check receiver
        if (methodSig.contains("HttpURLConnection: void connect")) {
            return isReceiverTainted(invoke, taintedVars);
        }

        // Default: check receiver
        return isReceiverTainted(invoke, taintedVars);
    }

    @Override
    public String getDescription() {
        return "Server-Side Request Forgery (SSRF) - URL.openConnection, DriverManager.getConnection";
    }
}
