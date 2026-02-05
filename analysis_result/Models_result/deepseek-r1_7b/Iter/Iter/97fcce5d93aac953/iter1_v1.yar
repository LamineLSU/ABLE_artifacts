rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule - focuses on setup and call sequences before exit"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B FF 55 EC }
        $pattern1 = { FF 75 08 10 E8 C8 83 C4 85 C0 0F 84 ?? ?? ?? ?? }
        $pattern2 = { 5A 8B CE ?? ?? ?? ?? 85 C0 }

    condition:
        any of them
}