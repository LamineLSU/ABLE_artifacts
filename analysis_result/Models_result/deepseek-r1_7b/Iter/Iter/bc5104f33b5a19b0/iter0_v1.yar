rule Bypass_Sample {
    meta:
        description = "Evasion bypass patterns targeting various dword ptr addresses"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 ?? ?? ?? ?? EA AA }
        $pattern1 = { E8 ?? 55 8B EC CA DD EC FC AC EA DC }
        $pattern2 = { ?? 74 1A ?? AE BA AC DA }

    condition:
        any of them
}