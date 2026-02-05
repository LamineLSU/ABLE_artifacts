rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 ?? ?? ?? ?? }
        $pattern1 = { 74 12 ?? ?? ?? ?? }
        $pattern2 = { 6A 5B ?? ?? ?? ?? }

    condition:
        any of them
}