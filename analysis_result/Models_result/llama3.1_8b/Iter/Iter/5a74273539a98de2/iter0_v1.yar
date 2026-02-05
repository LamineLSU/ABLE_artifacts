rule Bypass_Sample {
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern1+0,action0=skip,bp1=$pattern2+0,action1=skip,bp2=$pattern3+0,action2=skip,count=0"

    strings:
        $pattern1 = { FF ?? ?? AC ?? 41 ?? FF ?? ?? AC ?? 41 }
        $pattern2 = { FF ?? ?? 2C A1 ?? 26 ?? FF ?? ?? 2C A1 ?? 26 }
        $pattern3 = { FF ?? ?? 8C E1 ?? BA ?? FF ?? ?? 8C E1 ?? BA }

    condition:
        any of them
}