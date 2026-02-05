rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 55 8B EC FF 75 08 E8 ?? ?? ?? ?? 59 }
        $pattern1 = { 64 A1 30 00 00 00 8B 40 68 C1 E8 08 A8 01 75 10 }
        $pattern2 = { FF 15 AC B0 41 00 FF 15 3C E1 F1 00 50 FF 15 40 E1 F1 00 }

    condition:
        any of them
}