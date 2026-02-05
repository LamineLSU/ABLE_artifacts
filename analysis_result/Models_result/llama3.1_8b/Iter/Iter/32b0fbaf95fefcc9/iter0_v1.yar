rule Bypass_Sample {
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF D0 8B E5 83 EC ?? ?? ?? }
        $pattern1 = { 75 ?? ?? 8B E5 83 EC ?? ?? ?? }
        $pattern2 = { EB ?? ?? 8B E5 83 EC ?? ?? ?? }

    condition:
        any of them
}