rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF 15 BC 36 61 00 6A 04 56 BE C0 41 C8 17 56 }
        $pattern1 = { 6A 40 33 C0 59 C6 04 04 00 85 C0 75 00 40 }
        $pattern2 = { E8 44 C1 00 00 8B 15 54 34 61 00 E8 D8 F9 FF FF }

    condition:
        any of them
}