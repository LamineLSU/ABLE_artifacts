rule Bypass_Sample {
    meta:
        description = "Evasion bypass patterns found in two traces"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 ?? }
        $pattern1 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 74 0C }
        $pattern2 = { FF 74 24 10 ?? ?? ?? ?? ?? 75 0E ?? }

    condition:
        any of them
}