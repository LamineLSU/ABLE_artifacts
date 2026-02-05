rule Bypass_Sample {
    meta:
        description = "Evasion bypass patterns for sandbox evasion"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 45 14 5E 5D C3 }
        $pattern1 = { 8B 55 0C 56 6A 36 56 6A 00 51 51 }
        $pattern2 = { FD 5E 5D C3 }

    condition:
        any of them
}