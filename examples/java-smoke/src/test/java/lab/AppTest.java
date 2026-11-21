package lab;

import org.junit.Test;
import static org.junit.Assert.*;

public class AppTest {
    @Test public void whitespaceIsEmpty() { assertTrue(App.empty("  ")); }
    @Test public void textIsNotEmpty() { assertFalse(App.empty("hello")); }
}
