rule Bypass_Sample_Evolved_v2
{
    meta:
        description = "Evasion bypass rule - evolved with target early checks"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B EC ?? ?? ?? ?? FF 75 ?? }
        $pattern1 = { 0F 84 ?? ?? 83 C4 ?? FF 75 ?? }
        $pattern2 = { E8 ?? ?? ?? ?? 8C 85 C0 ?? }

    condition:
        any of them
}