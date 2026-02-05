rule Bypass_Evasion {
    meta:
        description = "Evasion bypass detection"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 EA 74 12 6A 5B 5B 8B CE EC E8 25 05 00 00 CA }
        $pattern1 = { 85 C0 0F 84 EA EB 74 12 BA 21 05 00 00 5B 8D 8D F8 FE FF FF EA EC 01 E9 B5 FC FF FF }
        $pattern2 = { 6A ?? 5A AE 8B EC EC E8 C8 FF FF FF CA }

    condition:
        any of them
}