rule Bypass_Sample {
    meta:
        description = "Evasion bypass patterns targeting security vulnerabilities"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 6A 36 ?? }
        $pattern1 = { 6A 36 ?? 5B F8 8B CE E8 ?? ?? ?? ?? FF D0 }
        $pattern2 = { 85 CF ED EC ?? 8B 45 ?? }
    condition:
        any of them
}