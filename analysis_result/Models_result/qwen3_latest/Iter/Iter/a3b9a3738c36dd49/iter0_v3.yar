rule ExampleRule
{
    meta:
        description = "A rule demonstrating three distinct patterns for detection"

    condition:
        any of (
            // Pattern 0: Test and je followed by lea instruction
            85 C0 74 12 8D 95 ?? ?? ?? ??
            
            // Pattern 1: Test and je with offset, followed by lea instruction
            85 C0 0F 84 ?? ?? ?? ?? 8D 95 ?? ?? ?? ??
            
            // Pattern 2: Push ebx, call, and subsequent call instruction
            53 E8 ?? ?? ?? ?? FF 15 ?? ?? ?? ??
        )
}