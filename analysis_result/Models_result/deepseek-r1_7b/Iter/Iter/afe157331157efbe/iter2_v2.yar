rule Bypass_Evasion {
    meta:
        description = "Evasion bypass analysis targeting exit process"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 C8 FF FF 59 FF 75 08 59 FF 75 08 FF 15 AC B0 41 00 }  // Combines call and surrounding pushes
        $pattern1 = { E8 C8 FF FF 59 FF 75 08 F5 C0 00 00 E8 C8 FF FF }    // Includes different offsets after call
        $pattern2 = { E8 C8 FF FF F5 A0 00 00 00 00 00 00 00 00 00 00 }   // Uses a unique offset sequence

    condition:
        any of them
}