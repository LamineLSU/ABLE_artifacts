rule Targeted_Bypass_Rule
{
    meta:
        description = "A refined rule to bypass detection by focusing on specific opcode sequences in the original sample."
        author = "Your Name"
        date = "2025-04-05"

    strings:
        // Pattern 1: First call to ExitProcess at 0x0040E7F6
        $call1 = { E8 C8 FFFF FF }

        // Pattern 2: Second call to ExitProcess at 0x0041B0AC
        $call2 = { FF 15 AC B0 41 00 }

        // Pattern 3: Push followed by the first call
        $push_call1 = { FF 75 08 E8 C8 FFFF FF }

    condition:
        $call1 or $call2 or $push_call1
}