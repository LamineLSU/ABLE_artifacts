rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass targeting ExitProcess"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B 00 00 00 5B }
        $pattern1 = { 83 F8 01 74 8B 4D EA EB 01 }
        $pattern2 = { 8E 4B 00 FF 00 AF 61 F0 }
    condition:
        any of them
}