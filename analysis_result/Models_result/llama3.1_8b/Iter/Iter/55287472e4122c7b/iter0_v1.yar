rule Bypass_Sample {
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 ?? FF 15 2C 64 ?? 50 }
        $pattern1 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 FF 75 FC }
        $pattern2 = { 68 C0 9E E6 05 6A 00 FF 75 FC E8 B9 ?? ?? ?? ?? 83 C4 }

    condition:
        any of them
}