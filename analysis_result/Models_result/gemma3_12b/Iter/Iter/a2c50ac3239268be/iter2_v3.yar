rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 50 50 E8 ?? ?? ?? ?? 8B 03 }
        $pattern1 = { 8B F0 55 8B EC 83 EC ?? 53 56 }
        $pattern2 = { 8B 45 ?? 8B F0 8B FB B9 0C 00 00 00 }

    condition:
        any of them
}