rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved using Strategy A and B"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 83 C4 01 74 00 00 00 00 00 00 }
        $pattern1 = { 6A 40 00 00 00 00 00 00 ?? }
        $pattern2 = { 5B 00 00 00 00 FF 87 F9 F6 FF 00 }

    condition:
        any of them
}