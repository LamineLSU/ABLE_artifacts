rule Bypass_Sample_Evasion {
    meta:
        description = "Evasion bypass analysis"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B EC F7 50 E8 C8 FF FF }
        $pattern1 = { 55 8B EC F7 50 E8 C8 FF FF }
        $pattern2 = { 8B FF 55 8B EC F7 50 E8 C8 FF FF }

    condition:
        any of them
}