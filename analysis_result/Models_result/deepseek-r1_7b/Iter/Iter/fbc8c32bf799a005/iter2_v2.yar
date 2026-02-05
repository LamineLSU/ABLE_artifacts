rule Bypass_Sample_Evasion {
    meta:
        description = "Evasion bypass analysis targeting specific instruction sequences"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? 75 0C }
        $pattern1 = { 75 0C ?? ?? ?? ?? 85 C0 }
        $pattern2 = { E8 ?? ?? ?? ?? 6A }

    condition:
        any of them
}