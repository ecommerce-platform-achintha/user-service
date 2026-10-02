package com.achintha.userservice.common;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

class CommonUtilitiesTest {

    private final PublicIdGenerator generator =
            new PublicIdGenerator(Clock.fixed(Instant.parse("2026-10-15T10:00:00Z"), ZoneOffset.UTC));

    @Test
    void publicIdsFollowTheContractFormat() {
        Set<String> ids = new HashSet<>();
        for (int i = 0; i < 2000; i++) {
            String id = generator.generate("USR");
            assertThat(id).matches("USR-2610-[0-9A-HJKMNP-TV-Z]{6}");
            assertThat(id.substring(9)).doesNotContain("I", "L", "O", "U");
            assertThat(PublicIdGenerator.isValid(id)).isTrue();
            ids.add(id);
        }
        assertThat(ids).hasSizeGreaterThan(1990); // random, not sequential
        assertThat(PublicIdGenerator.ALPHABET).hasSize(32).doesNotContain("I", "L", "O", "U");
    }

    @Test
    void generateUniqueRetriesOnCollisionAndGivesUp() {
        AtomicInteger calls = new AtomicInteger();
        String id = generator.generateUnique("ADR", candidate -> calls.incrementAndGet() < 3);
        assertThat(calls).hasValue(3);
        assertThat(id).startsWith("ADR-2610-");

        assertThatThrownBy(() -> generator.generateUnique("ADR", candidate -> true))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void sanitizerStripsMarkupAndKeepsPlainText() {
        assertThat(TextSanitizer.clean("<script>alert(1)</script>Hello <b>World</b>")).isEqualTo("Hello World");
        assertThat(TextSanitizer.clean("O'Brien & Sons")).isEqualTo("O'Brien & Sons");
        assertThat(TextSanitizer.clean("<img src=x onerror=alert(1)>")).isNull();
        assertThat(TextSanitizer.clean("&lt;script&gt;x")).isEqualTo("scriptx");
        assertThat(TextSanitizer.clean("a < b > c")).doesNotContain("<", ">");
        assertThat(TextSanitizer.cleanLine("  two\n lines\t ")).isEqualTo("two lines");
        assertThat(TextSanitizer.clean("   ")).isNull();
        assertThat(TextSanitizer.clean(null)).isNull();
    }

    @Test
    void nicValidationAndMasking() {
        assertThat(Nic.isValid("123456789V")).isTrue();
        assertThat(Nic.isValid("123456789x")).isTrue();
        assertThat(Nic.isValid("200012345678")).isTrue();
        assertThat(Nic.isValid("12345678V")).isFalse();
        assertThat(Nic.isValid("1234567890123")).isFalse();
        assertThat(Nic.isValid("12345678AV")).isFalse();
        assertThat(Nic.normalize(" 123456789v ")).isEqualTo("123456789V");
        assertThat(Nic.mask("200012345678")).isEqualTo("*********678");
        assertThat(Nic.mask("123456789V")).isEqualTo("*******89V");
    }
}
