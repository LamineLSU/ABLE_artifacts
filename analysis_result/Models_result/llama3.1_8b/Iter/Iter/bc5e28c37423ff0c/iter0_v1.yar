rule Bypass_Sample {
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 00 ?? ?? ?? FF D0 ?? ?? ?? ?? }
        $pattern1 = { 83 C4 14 ?? ?? ?? FF D0 ?? ?? }
        $pattern2 = { C3 ?? ?? ?? ?? FF D0 5E ?? }

    condition:
        any of them
}