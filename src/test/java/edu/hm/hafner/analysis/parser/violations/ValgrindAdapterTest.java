package edu.hm.hafner.analysis.parser.violations;

import edu.hm.hafner.analysis.AbstractParserTest;
import edu.hm.hafner.analysis.Report;
import edu.hm.hafner.analysis.Severity;
import edu.hm.hafner.analysis.assertions.SoftAssertions;

/**
 * Tests the class {@link ValgrindAdapter}.
 *
 * @author Tony Ciavarella
 */
class ValgrindAdapterTest extends AbstractParserTest {
    ValgrindAdapterTest() {
        super("valgrind.xml");
    }

    @Override
    protected void assertThatIssuesArePresent(final Report report, final SoftAssertions softly) {
        softly.assertThat(report).hasSize(3);
        softly.assertThat(report.get(1))
                .hasCategory("valgrind:memcheck")
                .hasMessage("Conditional jump or move depends on uninitialised value(s)")
                .hasFileName("/home/some_user/terrible_program/terrible_program.cpp")
                .hasType("UninitCondition")
                .hasLineStart(5)
                .hasSeverity(Severity.WARNING_HIGH);
        softly.assertThat(report.get(0))
                .hasCategory("valgrind:memcheck")
                .hasMessage("Invalid write of size 4")
                .hasFileName("/home/some_user/terrible_program/terrible_program.cpp")
                .hasType("InvalidWrite")
                .hasLineStart(10)
                .hasSeverity(Severity.WARNING_HIGH);
        softly.assertThat(report.get(2))
                .hasCategory("valgrind:memcheck")
                .hasMessage("16 bytes in 1 blocks are definitely lost in loss record 1 of 1")
                .hasFileName("/home/some_user/terrible_program/terrible_program.cpp")
                .hasType("Leak_DefinitelyLost")
                .hasLineStart(3)
                .hasSeverity(Severity.WARNING_HIGH);
    }

    @Override
    protected ValgrindAdapter createParser() {
        return new ValgrindAdapter();
    }
}
