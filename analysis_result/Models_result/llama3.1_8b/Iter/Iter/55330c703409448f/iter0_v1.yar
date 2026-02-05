rule Bypass_Sample {
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }
        $pattern1 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 ?? FF 15 AC B0 41 00 }
        $pattern2 = { FF 15 AC B0 41 00 FF 75 08 59 FF 75 08 6A ?? }

    condition:
        any of them
}