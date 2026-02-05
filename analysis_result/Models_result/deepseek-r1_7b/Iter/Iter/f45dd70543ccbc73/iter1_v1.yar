rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - specific points"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 4E 65 61 7A 4E 65 63 90 }
        $pattern1 = { 4E 65 61 83 4E 65 62 14 }
        $pattern2 = { 4E 65 62 16 4E 65 62 1A }

    condition:
        any of them
}