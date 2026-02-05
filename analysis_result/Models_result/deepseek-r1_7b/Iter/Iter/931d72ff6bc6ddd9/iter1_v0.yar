rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - targeting decision points before exit"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B 5A 8B CE E8 25 05 00 00 }
        $pattern1 = { 85 C0 74 12 6A 5B 5A 8B 85 F0 FE FF FF B9 42 8C 21 00 }
        $pattern2 = { 8D 43 01 8B 4D FC }

    condition:
        any of them
}