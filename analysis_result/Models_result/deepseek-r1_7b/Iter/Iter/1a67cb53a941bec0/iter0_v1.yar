rule Bypass_Sample {
    meta:
        description = "Evasion bypass detection for memory and conditional branches"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 ?? ?? ?? ?? 8B 45 ?? }
        $pattern1 = { E8 C8 FF FF ?? 5A 8B CE ?? ?? ?? ?? }
        $pattern2 = { 6A 5B 8B CE ?? ?? ?? ?? ?? ?? ?? ?? }
    condition:
        any of them
}