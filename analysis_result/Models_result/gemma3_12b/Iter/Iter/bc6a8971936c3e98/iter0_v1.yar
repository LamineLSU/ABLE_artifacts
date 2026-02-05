rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF 15 BC 36 61 00 50 FF 15 58 37 61 00 85 C0 75 07 }
        $pattern1 = { FF 15 94 37 61 00 CA DD 00 61 37 94 50 EA FF 15 58 37 61 00 CA DD 00 61 37 58 85 C0 EA EA 75 07 00 40 10 40 }
        $pattern2 = { FF 15 BC 36 61 00 CA DD 00 61 36 BC 6A 04 00 00 00 04 56 BE C0 41 C8 17 17 C8 41 C0 56 57 ED FF 15 EC 36 61 00 CA DD 00 61 36 EC }

    condition:
        any of them
}