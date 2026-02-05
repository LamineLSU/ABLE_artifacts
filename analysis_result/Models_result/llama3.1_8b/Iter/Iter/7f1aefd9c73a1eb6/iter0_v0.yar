rule Bypass_Sample {
    meta: description = "Evasion bypass rule"
    cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B CE E8 25 05 00 00 E8 74 FA FF FF CA 00 E3 66 7F }
        $pattern1 = { 6A ?? 5A 8B CE E8 25 05 00 00 CA 01 14 66 7F 85 C0 0F 84 ?? ?? ?? ?? }
        $pattern2 = { 8D 95 F0 FE FF FF EA EB EB 00 11 89 9D F0 FE FF FF EB 00 11 EB 8B CE }

    condition:
        any of them
}