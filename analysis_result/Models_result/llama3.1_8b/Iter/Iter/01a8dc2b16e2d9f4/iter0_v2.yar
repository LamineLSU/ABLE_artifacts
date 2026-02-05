rule Bypass_Sample {
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern+0,action0=skip,bp1=$pattern+12,action1=skip,bp2=$pattern+24,action2=skip,count=0"

    strings:
        $pattern = { FF 75 ?? 00 E8 ?? ?? ?? ?? C9 ?? }

    condition:
        any of them
}