rule Bypass_Sample {
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B CE E8 25 05 00 00 CA 00 B8 66 7F }
        $pattern1 = { 6A 5B 5A 8B CE E8 74 FA FF FF CA 00 B8 5C 17 85 C0 0F 84 ?? ?? ?? ?? }
        $pattern2 = { 8B FF 55 8B EC FF 75 08 DD EB 08 E8 C8 FF FF FF CA 00 40 E7 C3 }

    condition:
        any of them
}