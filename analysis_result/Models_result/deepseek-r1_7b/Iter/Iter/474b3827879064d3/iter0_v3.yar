rule Bypass_Sample {
    meta:
        description = "Evasion bypass patterns"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 ?? }
        $pattern1 = { E8 45 ?? ?? ?? ?? ?? ?? ?? ?? 31 61 F8 }
        $pattern2 = { EB 07 5D ?? ?? ?? ?? ?? ?? ?? ?? C3 }

    condition:
        any of them
}