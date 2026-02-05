rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - specifically targeting initial test and jump sequences"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 E8 25 05 00 00 }  // Initial test and jump
        $pattern1 = { 6A 5B 8B CE E8 25 05 00 00 }  // Another variation of the initial sequence
        $pattern2 = { 5A 74 12 E8 25 05 00 00 }    // Alternative starting steps

    condition:
        any of them
}