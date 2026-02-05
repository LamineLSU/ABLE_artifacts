rule CustomInstructionPattern
{
    meta:
        description = "Detects a specific sequence of instructions involving test, je, push, and call operations."
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"
        author = "Your Name"
        date = "2025-04-15"

    strings:
        // Pattern 0: Test and je instruction sequence
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? }

        // Pattern 1: Push and two call instructions
        $pattern1 = { 50 FF 15 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? }

        // Pattern 2: Call, test, and je instruction sequence
        $pattern2 = { E8 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? }

    condition:
        any of ($pattern0, $pattern1, $pattern2)
}