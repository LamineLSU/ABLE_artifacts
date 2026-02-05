rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B FF 55 8B EC E8 EA 59 00 00 84 C0 74 20 }
        $pattern1 = { 64 A1 30 00 00 00 8B 40 68 C1 E8 08 A8 01 75 10 }
        $pattern2 = { 83 F8 20 7F 0A E8 61 E4 FF FF }

    condition:
        any of them
}