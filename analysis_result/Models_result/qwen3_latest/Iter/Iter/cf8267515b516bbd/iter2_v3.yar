rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 52 8B 16 50 50 51 51 FF D2 }  // Pushes + call edx
        $pattern1 = { E8 ?? ?? ?? ?? }            // Variable-offset call
        $pattern2 = { C3 }                        // Return instruction

    condition:
        any of them
}