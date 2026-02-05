rule Bypass_Sample_Evolved {
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 00 00 ?? ?? ?? }
        $pattern1 = { 55 8B FF 45 FC ?? ?? }
        $pattern2 = { E8 3D 6C 00 ?? ?? }

    condition:
        any of them
}