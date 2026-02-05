rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 56 50 FF 15 C0 A0 41 00 FF 15 28 A2 41 00 }
        $pattern1 = { FF 75 08 E8 4E 00 00 00 FF 15 6C A1 15 0A }
        $pattern2 = { 8B 45 ?? 56 50 E8 6A 00 00 00 8B F0 }

    condition:
        any of them
}