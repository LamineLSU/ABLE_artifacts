rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 0E E8 E0 A2 FF FF }
        $pattern1 = { 85 C0 E8 B7 F7 FF FF 6A 00 FF 15 14 28 43 00 }
        $pattern2 = { 55 8B EC B9 F8 26 43 00 E8 43 1C 00 }

    condition:
        any of them
}