rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 41 B9 06 E8 F7 25 00 00 41 B9 03 55 41 B9 04 8B EC 41 B9 0A 01 0F 41 B9 0E 74 20 }
        $pattern1 = { 41 B9 06 E8 F7 25 00 00 41 B9 03 55 41 B9 04 8B EC 41 B9 0A 01 0F 41 B9 0E 74 20 41 B9 12 C2 FF }
        $pattern2 = { 41 B9 06 E8 F7 25 00 00 41 B9 03 55 41 B9 04 8B EC 41 B9 0A 01 0F 41 B9 0E 74 20 41 B9 16 E8 FF }
    condition:
        any of them
}