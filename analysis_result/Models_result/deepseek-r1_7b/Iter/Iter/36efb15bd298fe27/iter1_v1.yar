rule Bypass_Sample {
    meta:
        description = "Evasion bypass rule targeting call instructions."
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,count=0"

    strings:
        $pattern0 = { 8B EC FF7508 E8C8FFFFFF }
        $pattern1 = { 55 FF7508 E8C8FFFFFF }
        $pattern2 = { ?? FF7508 E8C8FFFFFF }
}

condition:
    any of them
}