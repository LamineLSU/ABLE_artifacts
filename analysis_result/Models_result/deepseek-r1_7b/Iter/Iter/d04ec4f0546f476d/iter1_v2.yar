rule Bypass_Sample {
    meta:
        description = "Evasion bypass analysis"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { EC EB ?? FF 75 08 }
        $pattern1 = { E8 ?? FF 15 08 ?? FF 15 08 }
        $pattern2 = { 6A ?? 5A 8B CE ?? 85 C0 }

    condition:
        any of them
}