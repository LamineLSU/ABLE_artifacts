rule EvasionBypass_Pattern0 {
    meta:
        description = "Evasion bypass using TEST EAX and subsequent call"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? E6 ?? ?? E6 ?? 12 8B 45 ?? ?? ?? ?? ?? ?? E8 4A 85 ?? ?? E7 ?? E9 }
    
        $pattern1 = { FF 15 54 A0 F6 00 8B DC ?? ?? ?? ?? ?? E8 3F 00 00 00 00 8D 04 85 ?? ?? E7 ?? E9 }
    
        $pattern2 = { FF 15 50 A0 F6 00 8B DC ?? ?? ?? ?? ?? E8 3F 00 00 00 00 8D 04 85 ?? ?? E7 ?? E9 }
    condition:
        any of them
}