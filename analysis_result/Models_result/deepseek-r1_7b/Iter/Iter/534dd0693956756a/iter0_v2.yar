rule EvasionBypass {
    meta:
        description = "Evasion bypass detection"
        cape_options = "$pattern0+0,action0=skip,$pattern1+0,action1=skip,$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 20 AC EF AE }
        $pattern1 = { 20 AC EC DA }
        $pattern2 = { 20 AC ED AE }

    condition:
        any of them
}