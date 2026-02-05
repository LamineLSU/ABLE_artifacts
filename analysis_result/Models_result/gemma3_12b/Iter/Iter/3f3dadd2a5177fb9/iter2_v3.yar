rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B FF 55 8B EC E8 F7 25 00 00 }
        $pattern1 = { 74 20 64 A1 30 00 00 00 8B 40 68 }
        $pattern2 = { 8B FF 55 8B EC E8 0B 00 00 00 59 }

    condition:
        any of them
}