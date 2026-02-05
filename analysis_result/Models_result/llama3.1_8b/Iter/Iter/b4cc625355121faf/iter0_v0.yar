rule Bypass_Sample {
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF 15 ?? ?? ?? ?? ?? CA ?? EF ?? }
        $pattern1 = { FF 15 ?? ?? ?? ?? ?? CA ?? 97 ?? }
        $pattern2 = { E8 ?? ?? ?? FF FF FF ?? C8 ?? }

    condition:
        any of them
}