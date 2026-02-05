rule Bypass_FunctionCalls {
    meta:
        description = "Evasion bypass detection for function call sequences"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 00 41 E1 A4 FF D2 FF FF FF 56 FF }
        $pattern1 = { 00 41 E1 B5 B0 0C 8B 00 00 00 00 }
        $pattern2 = { 00 41 E1 9F 5A 36 8B 07 00 00 00 }

    condition:
        any of them
}