rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - testing multiple strategies"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 0F 84 ?? ?? ?? ?? 8B 45 E8 }
        $pattern1 = { 85 C0 74 12 0F 84 ?? ?? ?? ?? EB 5E 85 }
        $pattern2 = { 8B CE 01 74 ?? ?? ?? ?? 53 }

    condition:
        any of them
}