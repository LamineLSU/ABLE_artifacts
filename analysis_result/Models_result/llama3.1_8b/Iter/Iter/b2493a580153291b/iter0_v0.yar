rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B FF 55 8B E5 E8 ?? ?? ?? ?? 83 F8 01 74 20 }
        $pattern1 = { 64 A1 30 00 00 00 8B 40 68 C1 E8 08 A0 01 75 10 }
        $pattern2 = { FF 15 52 F4 05 00 50 FF 15 A0 F4 05 00 }

    condition:
        any of them
}