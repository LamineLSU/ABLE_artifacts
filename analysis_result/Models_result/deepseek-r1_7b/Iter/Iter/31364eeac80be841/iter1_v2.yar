rule Bypass_Sample
{
    meta:
        description = "Evasion bypass detection for ExitProcess calls"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? }
        $pattern1 = { 8B 45 ?? .? ? ?? ?? ?? }
        $pattern2 = { FF 15 A0 F1 42 00 }
        
    condition:
        any of them
}