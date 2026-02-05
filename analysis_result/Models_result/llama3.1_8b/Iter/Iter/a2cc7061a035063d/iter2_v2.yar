rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 ?? ?? ?? ?? }
        $pattern1 = { 8B EC FF 75 ?? ?? }
        $pattern2 = { E8 ?? ?? ?? ?? 59 }

    condition:
        any of them
}