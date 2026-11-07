// Export a bounded, read-only Ghidra symbol/function inventory as JSON.
// @category middleManPS4
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import java.io.BufferedWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class ExportREInventory extends GhidraScript {
    private static final int MAX_LOCAL_FUNCTIONS = 10000;
    private static final int MAX_EXTERNAL_FUNCTIONS = 10000;

    private static String jsonString(String raw) {
        StringBuilder out = new StringBuilder("\"");
        for (int i = 0; i < raw.length(); i++) {
            char ch = raw.charAt(i);
            switch (ch) {
                case '"': out.append("\\\""); break;
                case '\\': out.append("\\\\"); break;
                case '\n': out.append("\\n"); break;
                case '\r': out.append("\\r"); break;
                case '\t': out.append("\\t"); break;
                default:
                    if (ch < 0x20) {
                        out.append(String.format("\\u%04x", (int) ch));
                    } else {
                        out.append(ch);
                    }
            }
        }
        return out.append('"').toString();
    }

    private boolean writeFunctions(BufferedWriter out, FunctionIterator funcs, int limit)
            throws Exception {
        int index = 0;
        while (funcs.hasNext() && index < limit) {
            if (monitor.isCancelled()) {
                throw new InterruptedException("Export cancelled");
            }
            Function function = funcs.next();
            String namespace = function.getParentNamespace() == null
                    ? "" : function.getParentNamespace().getName();
            if (index > 0) {
                out.write(",\n");
            }
            out.write("    {\"name\":" + jsonString(function.getName())
                    + ",\"namespace\":" + jsonString(namespace)
                    + ",\"entry\":" + jsonString(function.getEntryPoint().toString())
                    + "}");
            index++;
        }
        return funcs.hasNext();
    }

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 1) {
            throw new IllegalArgumentException("Expected one output JSON filename");
        }
        if (currentProgram == null) {
            throw new IllegalStateException("No program is loaded");
        }
        Path output = Paths.get(args[0]).toAbsolutePath().normalize();
        Path parent = output.getParent();
        if (parent == null || !Files.isDirectory(parent)) {
            throw new IllegalArgumentException("Output directory must already exist");
        }
        if (Files.exists(output)) {
            throw new IllegalArgumentException("Refusing to overwrite existing inventory");
        }

        FunctionIterator local = currentProgram.getFunctionManager().getFunctions(true);
        FunctionIterator external = currentProgram.getFunctionManager().getExternalFunctions();
        try (BufferedWriter out = Files.newBufferedWriter(output, StandardCharsets.UTF_8)) {
            out.write("{\n  \"format\":\"middleManPS4-ghidra-v1\",\n");
            out.write("  \"program\":" + jsonString(currentProgram.getName()) + ",\n");
            out.write("  \"language\":" +
                    jsonString(currentProgram.getLanguageID().toString()) + ",\n");
            out.write("  \"local_functions\":[\n");
            boolean localTruncated = writeFunctions(out, local, MAX_LOCAL_FUNCTIONS);
            out.write("\n  ],\n  \"external_functions\":[\n");
            boolean externalTruncated = writeFunctions(out, external, MAX_EXTERNAL_FUNCTIONS);
            out.write("\n  ],\n  \"local_truncated\":" + localTruncated
                    + ",\n  \"external_truncated\":" + externalTruncated + "\n}\n");
        }
        println("middleManPS4 function inventory written: " + output.getFileName());
    }
}
