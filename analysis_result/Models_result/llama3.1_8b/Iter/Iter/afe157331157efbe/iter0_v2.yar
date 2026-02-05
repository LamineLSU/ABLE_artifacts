rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B FF ?? 8B EC ?? FF 75 ?? E8 ?? ?? ?? ?? }
        $pattern1 = { 59 ?? FF 75 ?? FF 15 ?? ?? ?? ?? ?? }
        $pattern2 = { 55 ?? 8B EC ?? 8B FF ?? E8 ?? ?? ?? ?? }

    condition:
        any of them
}