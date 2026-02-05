rule Bypass_Evasion_Patterns
{
    meta:
        description = "Identifies patterns commonly used for evasion or obfuscation, such as conditional jumps and memory access operations."
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"
        author = "Your Name"
        date = "2025-04-15"

    strings:
        $pattern0 = { FF 15 ?? ?? ?? ?? 85 C0 75 ?? }
        $pattern1 = { 75 ?? 8B 45 ?? E8 ?? ?? ?? ?? }
        $pattern2 = { 85 C0 75 ?? 8B 45 ?? }

    condition:
        any of them
}