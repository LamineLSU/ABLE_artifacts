rule evasion_patterns
{
    meta:
        description = "Patterns indicative of evasion techniques or obfuscation"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"
        author = "Security Analyst"
        date = "2023-10-10"

    strings:
        $pattern0 = { 8B 4D 08 83 C4 14 52 FF D0 }
        $pattern1 = { 8B 45 ?? 83 C4 04 E8 ?? ?? ?? ?? }
        $pattern2 = { 83 C4 14 E8 ?? ?? ?? ?? }

    condition:
        any of them
}