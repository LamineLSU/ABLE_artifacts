rule Bypass_Sample {
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 F7 25 ?? ?? ?? ?? }  // Six bytes: E8 F7 25 followed by four displacement bytes (??)
        $pattern1 = { 0F 84 ?? ?? ?? ?? }     // Six bytes: 0F 84 followed by four ?? 
        $pattern2 = { FF 75 ?? ?? ?? ?? }     // Six bytes: FF 75 followed by four ??
    
    condition:
        any of them
}