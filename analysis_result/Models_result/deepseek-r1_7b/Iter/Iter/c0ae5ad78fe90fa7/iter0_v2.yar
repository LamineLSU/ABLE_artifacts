rule Bypass_Sample {
    meta:
        description: "Evasion bypass analysis for sandbox VM evasion"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 C8 FF FF F5 8B FF 55 8B EC ?? ?? ?? ?? FF 75 08 }
        $pattern1 = { FF 75 08 59 8B EC 8B FF 55 BE ?? ?? ?? ?? 83 C4 }
        $pattern2 = { E8 C8 FF FF F5 FF 75 08 59 8B FF 55 8B EC ?? ?? ?? 45 }

    condition:
        any of them
}