rule Bypass_Evasion_3 {
    meta:
        description = "Evasion via shr Operations"
        cape_options = "bp0=$pattern2+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern2 = { 75 8E 01 5D FF 75 08 E8 C8 FF FF FF FF 75 08 FF 15 AC B0 41 00 }
        // Include surrounding instructions to create a unique pattern

    condition:
        any of them
}