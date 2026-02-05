rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B EC 8B FC ?? ?? ?? ?? }
        $pattern1 = { 55 FF 75 08 8B FC 8B FC ?? ?? ?? }
        $pattern2 = { 55 FF 75 08 6A CE E8 FF 75 08 }
    condition:
        any of them
}