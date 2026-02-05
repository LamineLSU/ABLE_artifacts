rule Bypass_Sample {
    meta:
        description = "Evasion bypass for specific patterns targeting memory access"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 40 68 ?? C1 E8 ?? A8 01 ?? 75 10 ?? ?? }
        $pattern1 = { FF 75 08 E8 4F 00 ?? ?? ?? 59 C0 ?? } 
        $pattern2 = { 6A 00 ?? FF 75 08 ?? ?? ?? ?? }
}

condition:
    any of them
}