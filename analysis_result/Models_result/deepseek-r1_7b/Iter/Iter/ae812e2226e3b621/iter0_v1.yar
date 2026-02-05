rule Bypass_Sample {
    meta:
        description = "Evasion bypass patterns identified from exit process analysis"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 FF 15 88 A0 FF 6F FF }
        $pattern1 = { 8B FF 55 8B EC 5A E8 0B 00 00 00 FF 15 3C E1 29 00 }
        $pattern2 = { FF 15 AC B0 41 00 E8 0D 0C 94 00 D7 CF FF }
    
    condition:
        any of them
}