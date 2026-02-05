rule Bypass_Evasion {
    meta:
        description = "Malware bypass evasion detection"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 33 FF EA ?? ?? 74 07 ?? ?? 5A ?? 8B CE EC }
        $pattern1 = { 6A 5B 0B ?? 8B CE EC E8 25 05 00 00 CA DD ?? 33 CD EC EB 74 07 ?? ?? 5A ?? 8B CE EC }
        $pattern2 = { BA 21 05 00 00 ED 04 6A 40 00 00 00 40 E8 E3 FA FF FF CA DD ?? 74 07 ?? ?? 5A ?? 8B CE EC }

    condition:
        any of them
}