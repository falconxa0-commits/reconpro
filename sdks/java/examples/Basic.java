import com.reconpro.sdk.ReconProClient;
import com.reconpro.sdk.ReconProClient.SdkException;

import java.util.List;

/** Basic reconpro-sdk usage.  Run: java -cp build Basic [--offline] */
public class Basic {

    public static void main(String[] args) {
        boolean offline = List.of(args).contains("--offline");
        ReconProClient client = new ReconProClient();
        try {
            System.out.println("version: " + client.version());
            System.out.println("history: " + firstLine(client.history()));
            if (offline) {
                System.out.println("scan skipped (--offline)");
            } else {
                String scan = client.scan("example.com");
                System.out.println("scan: " + scan.substring(0, Math.min(200, scan.length())) + "...");
            }
        } catch (SdkException e) {
            System.err.println("sdk error (exit " + e.exitCode + "): " + e.getMessage());
            System.exit(1);
        }
    }

    private static String firstLine(String text) {
        int newline = text.indexOf('\n');
        return newline < 0 ? text : text.substring(0, newline);
    }
}
