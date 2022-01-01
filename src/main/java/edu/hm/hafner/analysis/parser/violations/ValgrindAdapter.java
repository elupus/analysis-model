package edu.hm.hafner.analysis.parser.violations;

import java.util.Map;
import java.util.Set;

import javax.annotation.Nullable;

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
    Report convertToReport(Set<Violation> violations) {
        try (IssueBuilder issueBuilder = new IssueBuilder()) {
            Report report = new Report();

            for (Violation violation: violations) {
                updateIssueBuilder(violation, issueBuilder);
                issueBuilder.setCategory("valgrind:" + violation.getReporter());

                StringBuilder description = new StringBuilder();

                description.append("<table>");

                maybeAppendTableRow(description, "Executable", violation.getSource());
                maybeAppendTableRow(description, "Unique Id", violation.getGroup());

                Map<String, String> specifics = violation.getSpecifics();
                JSONArray auxWhats = null;

                if ((specifics != null) && !specifics.isEmpty()) {
                    maybeAppendTableRow(description, "Thread Id", specifics.get("tid"));
                    maybeAppendTableRow(description, "Thread Name", specifics.get("threadname"));

                    String auxWhatsJson = specifics.get("auxwhats");

                    if ((auxWhatsJson != null) && !auxWhatsJson.isEmpty()) {
                        try {
                            JSONTokener json = new JSONTokener(auxWhatsJson);
                            auxWhats = new JSONArray(json);

                            for (int auxwhatIndex=0; auxwhatIndex < auxWhats.length(); ++auxwhatIndex) {
                                maybeAppendTableRow(description, "Auxiliary", auxWhats.getString(auxwhatIndex));
                            }
                        }
                        catch (JSONException ignored) {
                        }
                    }
                }

                description.append("</table>");

                if ((specifics != null) && !specifics.isEmpty()) {
                    try {
                        JSONTokener json = new JSONTokener(specifics.get("stacks"));
                        JSONArray stacks = new JSONArray(json);

                        for (int stackIndex=0; stackIndex < stacks.length(); ++stackIndex) {
                            description.append("<h2>");
                            if (stackIndex == 0) {
                                description.append("Primary Stack Trace</h2><h3>")
                                           .append(violation.getMessage())
                                           .append("</h3>");
                            } else {
                                description.append("Auxiliary Stack Trace");

                                if (stacks.length() > 2) {
                                    description.append(" #").append(stackIndex);
                                }

                                description.append("</h2>");

                                if ((auxWhats != null) && (auxWhats.length() >= stackIndex)) {
                                    description
                                            .append("<h3>")
                                            .append(auxWhats.getString(stackIndex - 1))
                                            .append("</h3>");
                                }
                            }

                            JSONArray frames = stacks.getJSONArray(stackIndex);

                            for (int frameIndex=0; frameIndex < frames.length(); ++frameIndex) {
                                JSONObject frame = frames.getJSONObject(frameIndex);

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
                    }
                    catch (JSONException ignored) {
                    }

                    String suppression = specifics.get("suppression");

                    if ((suppression != null) && !suppression.isEmpty()) {
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

    private void maybeAppendTableRow(StringBuilder html, String name, @Nullable String value) {
        if ((value != null) && !value.isEmpty()) {
            html
                    .append("<tr><td class=\"pane-header\">")
                    .append(name)
                    .append("</td><td class=\"pane\">")
                    .append(value)
                    .append("</td></tr>");
        }
    }

    private void maybeAppendStackFrameFileTableRow(StringBuilder html, JSONObject frame) throws JSONException {
        String dir = frame.optString("dir");
        String file = frame.optString("file");
        int line = frame.optInt("line", -1);

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