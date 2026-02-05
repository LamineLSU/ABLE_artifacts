rule Bypass_Sample {
    meta:
        description = "Evasion bypass analysis by skipping critical instructions"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 74 20 E8 ?? ?? ?? ?? ?? } 
        $pattern1 = { FF 75 08 8B 40 68 C1 E8 ?? ?? }
        $pattern2 = { 83 F8 01 74 20 E8 ?? ?? }

    condition:
        any()
}