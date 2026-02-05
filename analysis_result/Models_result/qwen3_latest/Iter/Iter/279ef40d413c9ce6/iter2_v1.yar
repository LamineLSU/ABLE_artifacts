rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 74 10 6A 00 FF 15 ?? ?? ?? ?? }
        $pattern1 = { 75 32 8B 45 ?? E8 ?? ?? ?? ?? }
        $pattern2 = { E9 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? }

    condition:
        any of them
}