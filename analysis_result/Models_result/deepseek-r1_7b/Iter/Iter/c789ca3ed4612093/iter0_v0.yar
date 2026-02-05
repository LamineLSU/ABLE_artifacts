rule EvasionBypass {
    meta:
        description = "Evasion bypass patterns targeting specific code paths"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 60 55 8B EC ?? ?? ?? ?? ?? }
        $pattern1 = { C1 E8 75 10 ?? ?? }
        $pattern2 = { 64 A1 30 00 ?? ?? ?? }

    condition:
        any of them
}