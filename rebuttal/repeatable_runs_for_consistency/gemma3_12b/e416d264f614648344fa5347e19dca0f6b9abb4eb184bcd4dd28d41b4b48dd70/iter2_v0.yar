rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8D 4C 24 30 E8 6C 7E 01 00 }
        $pattern1 = { 8B CC 53 E8 AC 9E FF FF }
        $pattern2 = { 68 44 41 46 00 E8 2A 03 00 00 }

    condition:
        any of them
}