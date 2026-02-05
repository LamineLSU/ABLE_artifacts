rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass targeting exit decision points"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B 5A 8B CE E8 25 05 00 00 }
        $pattern1 = { 55 8B EC FF 75 08 55 8D 43 01 5F }
        $pattern2 = { 8B 4D FC 5B 8B E5 5D E8 57 26 00 00 C3 }

    condition:
        any of them
}