rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? 85 C0 74 }
        $pattern1 = { 83 F8 01 74 12 8B 4D F8 }
        $pattern2 = { 0F 31 C9 8B CB E4 BF 01 }

    condition:
        any of them
}