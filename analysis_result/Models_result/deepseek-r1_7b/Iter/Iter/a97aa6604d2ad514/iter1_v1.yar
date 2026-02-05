rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule targeting API calls"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B EC ?? ?? ?? ?? 5E 4F }
        $pattern1 = { E8 ?? ?? ?? ?? 74 ?? }
        $pattern2 = { 6A ?? ?? ?? ?? 8B CE }

    condition:
        any of them
}