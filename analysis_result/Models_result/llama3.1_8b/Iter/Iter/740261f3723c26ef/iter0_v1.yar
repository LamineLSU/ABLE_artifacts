rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B FF 55 8B EC E8 ?? ?? ?? ?? }
        $pattern1 = { E8 ?? ?? ?? AC B0 41 10 }
        $pattern2 = { FF ?? ?? ?? 59 5A 83 C4 ?? }

    condition:
        any of them
}