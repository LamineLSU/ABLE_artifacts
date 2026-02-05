rule Bypass_Sample {
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF D3 46 83 FE 1A ?? ?? ?? ?? }
        $pattern1 = { FF D7 50 6A FF ?? ?? ?? ?? }
        $pattern2 = { 6A FF FF 35 ?? ?? ?? ?? FF 15 78 ?? ?? }

    condition:
        any of them
}