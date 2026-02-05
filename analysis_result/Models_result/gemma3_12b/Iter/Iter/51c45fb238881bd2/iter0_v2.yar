rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF 96 B0 00 00 00 00 FF 45 E8 83 7D E8 14 FF 82 BE 20 00 00 }
        $pattern1 = { E8 2D FD FF FF 83 7D E8 14 FF 82 BE 20 00 00 0F 85 F2 C0 FF FF }
        $pattern2 = { E8 9C 1B 00 00 8B 7B 10 8B 7B 10 85 FF 74 1C 8B 6B 10 }

    condition:
        any of them
}