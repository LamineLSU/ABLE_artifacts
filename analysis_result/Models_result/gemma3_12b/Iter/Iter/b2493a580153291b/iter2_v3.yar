rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B FF 55 8B EC E8 17 D0 00 00 83 F8 01 74 20 }
        $pattern1 = { 64 A1 ?? ?? ?? ?? 8B 40 68 C1 E8 08 A8 01 75 10 FF 75 08 }
        $pattern2 = { FF 15 8C 50 F4 00 50 FF 15 A0 50 F4 00 FF 75 08 E8 4F 00 00 00 59 FF 75 08 }

    condition:
        any of them
}