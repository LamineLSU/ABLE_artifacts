rule Bypass_Sample {
    meta:
        description = "Evasion bypass rules targeting suspicious code paths"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 5A C9 FF 8B 45 E8 ?? ?? ?? ?? 6A 5A }
        $pattern1 = { CA FF 75 08 0F 8C ?? ?? ?? ?? 28 5A }
        $pattern2 = { CC 33 5D F9 8B EC ?? ?? ?? ?? C9 45 }

    condition:
        (any_of($pattern0, $pattern1, $pattern2))
}