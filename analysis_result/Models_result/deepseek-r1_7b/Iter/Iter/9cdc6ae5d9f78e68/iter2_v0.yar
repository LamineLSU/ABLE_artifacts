rule Bypass_Evasion {
    meta:
        description = "Detects bypass evasions through different instruction sequences"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? }
        $pattern1 = { 74 ?? ?? ?? }
        $pattern2 = { 6A 8B CE E8 ?? }

    condition:
        any_ofthem
}