rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B FF 55 8B EC E8 EA 59 00 00 84 C0 }
        $pattern1 = { 64 A1 30 00 00 00 8B 40 68 C1 E8 08 A8 01 75 10 }
        $pattern2 = { FF 75 08 FF 15 BC 92 45 00 50 FF 15 D4 92 45 00 }

    condition:
        any of them
}