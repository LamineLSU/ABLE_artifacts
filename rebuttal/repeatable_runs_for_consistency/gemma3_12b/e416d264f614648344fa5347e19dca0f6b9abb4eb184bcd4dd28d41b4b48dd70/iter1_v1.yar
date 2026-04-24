rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 83 C4 20 68 B8 0B 00 00 FF 15 B0 62 45 00 }
        $pattern1 = { 85 C0 74 12 6A 01 83 EC 18 8B CC 53 E8 AC 9E FF }
        $pattern2 = { 8D 4C 24 30 E8 6C 7E 01 00 8B C8 E8 0C 03 00 00 }

    condition:
        any of them
}