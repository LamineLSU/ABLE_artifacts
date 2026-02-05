rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 83 F8 01 74 12 8B 4D }
        $pattern1 = { 8B FF 55 8B EC 83 F8 01 }
        $pattern2 = { 55 8B EC E8 9D 21 00 00 }

    condition:
        any of them
}