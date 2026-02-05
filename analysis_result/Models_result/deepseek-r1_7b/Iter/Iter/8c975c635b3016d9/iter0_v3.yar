rule Bypass_Sample {
    meta: description = "Evasion bypass patterns targeting conditional jumps and memory accesses"
    cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A 04 8B CE E8 2C 3E 5F 5E 39 17 }
        $pattern1 = { 8B 45 00 00 5A 00 00 }
        $pattern2 = { 8B 4D 00 5E 00 00 }

    condition:
        any of them
}