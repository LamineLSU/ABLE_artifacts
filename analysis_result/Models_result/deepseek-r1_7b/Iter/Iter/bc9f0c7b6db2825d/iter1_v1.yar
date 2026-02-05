rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass targeting specific exit decision points"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B 8B CE E8 25 05 00 00 }
        $pattern1 = { 33 DB 74 07 8B CE E8 4B 17 00 00 }
        $pattern2 = { 85 C0 74 12 6A 5B E8 4B 17 00 00 }

    condition:
        any of them
}