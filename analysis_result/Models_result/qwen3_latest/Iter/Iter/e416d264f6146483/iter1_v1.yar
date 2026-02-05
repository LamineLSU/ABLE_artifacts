rule Bypass_Evasion_Patterns
{
    meta:
        description = "Detects patterns indicative of evasion logic or obfuscation."
        author = "Your Name"
        date = "2025-04-05"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip"

    strings:
        $pattern0 = FF 15 ?? ?? ?? ??  // Call to a function (e.g., Sleep, GetProcAddress)
        $pattern1 = E8 ?? ?? ?? ??     // Call to a function (offset-based)
        $pattern2 = 55 8B D6 8D 4C 24 30 E8 6C 7E 01 00  // Sequence of push ebp, mov edx, lea ecx, call

    condition:
        all of them
}