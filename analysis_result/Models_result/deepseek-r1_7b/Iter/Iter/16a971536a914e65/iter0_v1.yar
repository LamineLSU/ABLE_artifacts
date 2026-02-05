rule Bypass_Sample
{
    meta:
        description = "Evasion bypass for exit process"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 45 5A ?? ?? ?? ?? E8 45 F7 00 00 }  # Bypassing conditional jump
        $pattern1 = { 8E 0D FC 5D ?? ?? ?? ?? E9 B5 FC FF FF }  # Skipping function call
        $pattern2 = { ?? ?? ?? ?? 68 40 11 33 01 E8 E3 FA FF FF }  # Bypassing push instruction

    condition:
        any of them
}