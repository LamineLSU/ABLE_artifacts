rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 45 ?? ?? ?? ?? 8B EC ?? }
        $pattern1 = { E8 ?? ?? ?? ?? ?? 5E EB FF C0 83 C4 ?? AD 14 5A EC }
        $pattern2 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 8B EC ?? }

    condition:
        any of them
}