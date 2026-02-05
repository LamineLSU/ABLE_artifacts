rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? }
        $pattern1 = { E8 ?? ?? ?? ?? 83 F8 01 }
        $pattern2 = { 74 12 8B 4D F8 03 C3 }

    condition:
        any of them
}