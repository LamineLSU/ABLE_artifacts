rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? B9 0A 00 00 00 33 D2 F7 F1 83 FA 05 75 02 } // div + cmp + jne evasion check
        $pattern1 = { EB E9 E8 ?? ?? ?? ?? } // loop + exit call sequence
        $pattern2 = { 6A 00 E8 ?? ?? ?? ?? } // push 0 + exit call sequence

    condition:
        any of them
}