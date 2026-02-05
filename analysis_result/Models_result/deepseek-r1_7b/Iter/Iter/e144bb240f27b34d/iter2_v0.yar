rule Bypass_Sample {
    meta:
        description = "Evasion bypass for sample E144bb240f27b34db"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 55 C0 0F 8B EC E8 ?? }
        $pattern1 = { 6A ?? 5A 8B CE E8 ?? }
        $pattern2 = { FF 75 00 00 20 8C 45 ?? }

    condition:
        any of them
}