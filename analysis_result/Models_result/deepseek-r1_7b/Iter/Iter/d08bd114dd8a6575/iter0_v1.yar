rule Bypass_Sample {
    meta:
        description = "Evasion bypass detection patterns"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 45 ?? 56 EB EA DD EB 13 ?? ?? }

        $pattern1 = { 8D 0A EB EA DD ED 45 ?? ?? }

        $pattern2 = { 8B C4 00 EA 12 34 56 78 ?? ?? }
    condition:
        any of them
}