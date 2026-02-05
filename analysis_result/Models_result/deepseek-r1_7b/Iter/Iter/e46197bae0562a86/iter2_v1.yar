rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - targeted specific instruction sequences"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 00 94 5E 83 }
        $pattern1 = { 00 94 61 F7 E8 BE C3 }
        $pattern2 = { 00 94 61 DB 53 00 94 5E 85 }

    condition:
        any of them
}