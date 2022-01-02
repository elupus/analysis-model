package edu.hm.hafner.analysis.parser.violations;

import java.util.Map;
import java.util.Set;

import org.apache.commons.text.StringEscapeUtils;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONTokener;

import edu.hm.hafner.analysis.IssueBuilder;
import edu.hm.hafner.analysis.Report;

import edu.umd.cs.findbugs.annotations.CheckForNull;

import se.bjurr.violations.lib.model.Violation;
import se.bjurr.violations.lib.parsers.ValgrindParser;

/**
 * Parses Valgrind XML report files.
 *
 * @author Tony Ciavarella
 */
public class ValgrindAdapter extends AbstractViolationAdapter {
    private static final long serialVersionUID = -6117336551972081612L;
    private static final int NUMBERED_STACK_THRESHOLD = 2;

    @Override
    ValgrindParser createParser() {
        return new ValgrindParser();
    }

    @Override
    Report convertToReport(final Set<Violation> violations) {
        try (IssueBuilder issueBuilder = new IssueBuilder()) {
            Report report = new Report();

            for (Violation violation: violations) {
                updateIssueBuilder(violation, issueBuilder);
                issueBuilder.setCategory("valgrind:" + violation.getReporter());
                issueBuilder.setDescription(generateDescriptionHtml(violation));
                report.add(issueBuilder.buildAndClean());
            }

            return report;
        }
    }

    private String generateDescriptionHtml(final Violation violation) {
        final StringBuilder description = new StringBuilder(512);

        final Map<String, String> specifics = violation.getSpecifics();
        final JSONArray auxWhats = getAuxWhatsArray(specifics);

        appendGeneralTable(description, violation.getSource(), violation.getGroup(), specifics.get("tid"), specifics.get("threadname"), auxWhats);
        maybeAppendStackTraces(description, specifics.get("stacks"), violation.getMessage(), auxWhats);
        maybeAppendSuppression(description, specifics.get("suppression"));

        return description.toString();
    }

    private void appendGeneralTable(final StringBuilder html, final String executable, final String uniqueId, @CheckForNull final String threadId, @CheckForNull final String threadName, @CheckForNull final JSONArray auxWhats) {
        html.append("<table>");

        maybeAppendTableRow(html, "Executable", executable);
        maybeAppendTableRow(html, "Unique Id", uniqueId);
        maybeAppendTableRow(html, "Thread Id", threadId);
        maybeAppendTableRow(html, "Thread Name", threadName);

        if (auxWhats != null && !auxWhats.isEmpty()) {
            for (int auxwhatIndex = 0; auxwhatIndex < auxWhats.length(); ++auxwhatIndex) {
                maybeAppendTableRow(html, "Auxiliary", auxWhats.getString(auxwhatIndex));
            }
        }

        html.append("</table>");
    }

    private void maybeAppendStackTraces(final StringBuilder html, @CheckForNull final String stacksJson, final String message, @CheckForNull final JSONArray auxWhats) {
        if (stacksJson == null || stacksJson.isEmpty()) {
            return;
        }

        final JSONArray stacks = new JSONArray(new JSONTokener(stacksJson));

        if (!stacks.isEmpty()) {
            appendStackTrace(html, "Primary Stack Trace", message, stacks.getJSONArray(0));

            for (int stackIndex = 1; stackIndex < stacks.length(); ++stackIndex) {
                String msg = null;

                if (auxWhats != null && auxWhats.length() >= stackIndex) {
                    msg = auxWhats.getString(stackIndex - 1);
                }

                String title = "Auxiliary Stack Trace";

                if (stacks.length() > NUMBERED_STACK_THRESHOLD) {
                    title = "Auxiliary Stack Trace #" + stackIndex;
                }

                appendStackTrace(html, title, msg, stacks.getJSONArray(stackIndex));
            }
        }
    }

    private void appendStackTrace(final StringBuilder html, final String title, @CheckForNull final String message, final JSONArray frames) {
        html
                .append("<h2>")
                .append(title)
                .append("</h2>");

        if (message != null && !message.isEmpty()) {
            html
                    .append("<h3>")
                    .append(message)
                    .append("</h3>");
        }

        for (int frameIndex = 0; frameIndex < frames.length(); ++frameIndex) {
            final JSONObject frame = frames.getJSONObject(frameIndex);

            if (frameIndex > 0) {
                html.append("<br>");
            }

            appendStackFrame(html, frame);
        }
    }

    private void appendStackFrame(final StringBuilder html, final JSONObject frame) {
        html.append("<table>");
        maybeAppendTableRow(html, "Object", frame.getString("obj"));
        maybeAppendTableRow(html, "Function", frame.getString("fn"));
        maybeAppendStackFrameFileTableRow(html, frame);
        html.append("</table>");
    }

    private void maybeAppendSuppression(final StringBuilder html, @CheckForNull final String suppression) {
        if (suppression != null && !suppression.isEmpty()) {
            html
                    .append("<h2>Suppression</h2><table><tr><td class=\"pane\"><pre>")
                    .append(StringEscapeUtils.escapeHtml4(suppression))
                    .append("</pre></td></tr></table>");
        }
    }

    private void maybeAppendTableRow(final StringBuilder html, final String name, @CheckForNull final String value) {
        if (value != null && !value.isEmpty()) {
            html
                    .append("<tr><td class=\"pane-header\">")
                    .append(name)
                    .append("</td><td class=\"pane\">")
                    .append(value)
                    .append("</td></tr>");
        }
    }

    private void maybeAppendStackFrameFileTableRow(final StringBuilder html, final JSONObject frame) throws JSONException {
        String dir = frame.optString("dir");
        final String file = frame.optString("file");
        final int line = frame.optInt("line", -1);

        if (!file.isEmpty()) {
            html.append("<tr><td class=\"pane-header\">File</td><td class=\"pane\">");

            if (!dir.isEmpty()) {
                html.append(dir).append('/');
            }

            html.append(file);

            if (line != -1) {
                html.append(':').append(line);
            }

            html.append("</td></tr>");
        }
    }

    @CheckForNull
    private JSONArray getAuxWhatsArray(final Map<String, String> specifics) {
        final String auxWhatsJson = specifics.get("auxwhats");

        if (auxWhatsJson != null && !auxWhatsJson.isEmpty()) {
            return new JSONArray(new JSONTokener(auxWhatsJson));
        }

        return null;
    }
}