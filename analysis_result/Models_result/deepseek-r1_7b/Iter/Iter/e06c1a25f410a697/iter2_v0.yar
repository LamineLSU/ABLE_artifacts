rule Bypass_Sample_Evolved {
    meta:
        description = "Evasion bypass rule - more targeted approach"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"
    
    strings:
        $pattern0 = { 00 85 C0 74 12 6A 5B ?? ?? ?? ?? EA EA }
        $pattern1 = { 00 85 C0 6A 5B ?? ?? EA EA ?? ?? }
        $pattern2 = { 00 8B CE 74 12 6A 5B ?? ?? EA EA ?? ?? }
}

condition:
    (any of ($pattern0 | $pattern1 | $pattern2))