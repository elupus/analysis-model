package edu.hm.hafner.analysis.parser.violations;

import java.util.Map;
import java.util.Set;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONTokener;

import edu.hm.hafner.analysis.IssueBuilder;
import edu.hm.hafner.analysis.Report;

import se.bjurr.violations.lib.model.Violation;
import se.bjurr.violations.lib.parsers.ValgrindParser;

/**
 * Parses Valgrind XML report files.
 *
 * @author Tony Ciavarella
 */
public class ValgrindAdapter extends AbstractViolationAdapter {
    private static final long serialVersionUID = -6117336551972081612L;

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

                final StringBuilder description = new StringBuilder(512);

                description.append("<table>");

                maybeAppendTableRow(description, "Executable", violation.getSource());
                maybeAppendTableRow(description, "Unique Id", violation.getGroup());

                final Map<String, String> specifics = violation.getSpecifics();
                JSONArray auxWhats = null;

                if (specifics != null && !specifics.isEmpty()) {
                    maybeAppendTableRow(description, "Thread Id", specifics.get("tid"));
                    maybeAppendTableRow(description, "Thread Name", specifics.get("threadname"));

                    final String auxWhatsJson = specifics.get("auxwhats");

                    if (auxWhatsJson != null && !auxWhatsJson.isEmpty()) {
                        final JSONTokener json = new JSONTokener(auxWhatsJson);
                        auxWhats = new JSONArray(json);

                        for (int auxwhatIndex = 0; auxwhatIndex < auxWhats.length(); ++auxwhatIndex) {
                            maybeAppendTableRow(description, "Auxiliary", auxWhats.getString(auxwhatIndex));
                        }
                    }
                }

                description.append("</table>");

                if (specifics != null && !specifics.isEmpty()) {
                    final JSONTokener json = new JSONTokener(specifics.get("stacks"));
                    final JSONArray stacks = new JSONArray(json);

                    for (int stackIndex = 0; stackIndex < stacks.length(); ++stackIndex) {
                        description.append("<h2>");
                        if (stackIndex == 0) {
                            description.append("Primary Stack Trace</h2><h3>")
                                       .append(violation.getMessage())
                                       .append("</h3>");
                        }
                        else {
                            description.append("Auxiliary Stack Trace");

                            if (stacks.length() > 2) {
                                description.append(" #").append(stackIndex);
                            }

                            description.append("</h2>");

                            if (auxWhats != null && auxWhats.length() >= stackIndex) {
                                description
                                        .append("<h3>")
                                        .append(auxWhats.getString(stackIndex - 1))
                                        .append("</h3>");
                            }
                        }

                        final JSONArray frames = stacks.getJSONArray(stackIndex);

                        for (int frameIndex = 0; frameIndex < frames.length(); ++frameIndex) {
                            final JSONObject frame = frames.getJSONObject(frameIndex);

                            if (frameIndex > 0) {
                                description.append("<br>");
                            }

                            description.append("<table>");
                            maybeAppendTableRow(description, "Object", frame.getString("obj"));
                            maybeAppendTableRow(description, "Function", frame.getString("fn"));
                            maybeAppendStackFrameFileTableRow(description, frame);
                            description.append("</table>");
                        }
                    }

                    final String suppression = specifics.get("suppression");

                    if (suppression != null && !suppression.isEmpty()) {
                        description
                                .append("<h2>Suppression</h2><table><tr><td class=\"pane\"><pre>")
                                .append(suppression)
                                .append("</pre></td></tr></table>");
                    }
                }

                issueBuilder.setDescription(description.toString());
                report.add(issueBuilder.buildAndClean());
            }

            return report;
        }
    }

    private void maybeAppendTableRow(final StringBuilder html, final String name, final String value) {
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
}