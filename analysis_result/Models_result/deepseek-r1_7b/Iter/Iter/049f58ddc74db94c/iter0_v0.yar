rule Bypass_Evasion {
    meta:
        description = "Evasion bypass detection"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B E8 CE ?? FE FF FF }
        $pattern1 = { E8 CE 8B CE 0F 84 33 CF 55 00 00 00 5B ?? 0F 84 33 FD FF FF FF 0F 84 33 FD FF FF FF ?? }
        $pattern2 = { E8 CE EC FF 5E 07 8D 95 F0 FF FF FF 8D 95 F0 FF FF FF FC 01 00 00 00 00 00 00 00 00 00 ?? }

    condition:
        any_of($pattern0, $pattern1, $pattern2)
}