rule Bypass_Evasion {
    meta:
        description = "Evasion bypass detection"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 45 E8 C8 ?? ?? ?? ?? ?? } // Includes a call with unknown offset
        $pattern1 = { E8 C8 ?? ?? ?? ?? 8B 4D FC } // Targets an unknown offset after call
        $pattern2 = { FF 15 AC B0 41 00 8B 45 E8 C8 ?? ?? ?? } // Includes a call with specific address
    condition:
        any of them
}