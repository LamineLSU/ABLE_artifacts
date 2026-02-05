rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 90 85 C0 74 08 } // Skip the je instruction
        $pattern1 = { 8B 8B E8 70 84 FF FF 85 C0 } // Bypass the initial call
        $pattern2 = { 8B 82 E8 FD AF FF FF 85 C0 } // Bypass the initial call

    condition:
        any of them
}