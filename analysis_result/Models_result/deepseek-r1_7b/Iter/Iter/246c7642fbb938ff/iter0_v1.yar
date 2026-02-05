rule Bypass_Evasion {
    meta:
        description = "Detects bypass evasions through call instructions"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B C8 E8 ?? ?? ?? ??. }  // Setup leading to call with wildcards
        $pattern1 = { E8 ?? ?? ?? ??. }         // Call instruction focusing on displacement
        $pattern2 = { FF7508 8B C8 E8 ?? ?? ?? ??. }  // Alternative access point with wildcards
}