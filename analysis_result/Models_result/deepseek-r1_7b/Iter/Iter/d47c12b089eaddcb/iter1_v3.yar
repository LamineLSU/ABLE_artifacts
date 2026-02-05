rule Bypass_Sample {
    meta:
        description = "Evasion bypass based on call instruction displacement"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? E8 ?? ?? }
        $pattern1 = { FF C8 FF FF FF F5 F8 ?? ?? 8B 45 }
        $pattern2 = { FF C4 ?? ?? 8B 45 FF 75 08 }

    condition:
        any of them
}