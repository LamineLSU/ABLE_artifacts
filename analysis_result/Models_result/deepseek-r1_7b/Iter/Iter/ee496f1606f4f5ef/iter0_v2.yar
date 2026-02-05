rule Bypass_Sample {
    meta:
        description = "Evasion bypass detection"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A 5D FF 15 88 7C } 
        $pattern1 = { 6A 5F E8 4B FF 95 ?? }
        $pattern2 = { 6A 5E FF FF FF 5C ?? }
    condition:
        any of them
}