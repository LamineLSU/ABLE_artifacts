rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B ?? ?? E8 ?? ?? ?? ?? 83 EC ?? }
        $pattern1 = { FF D5 ?? ?? 84 ?? ?? ?? ?? 8B 4D ?? }
        $pattern2 = { B8 ?? ?? ?? ?? C3 83 EC ?? }

    condition:
        any of them
}