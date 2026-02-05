rule SkipSandboxCheck {
    meta:
        description = "Skips the sandbox check by skipping the test and jump instructions"
    condition:
        85 C0 74 ?? // Test EAX, EAX followed by a conditional jump (JE)
}