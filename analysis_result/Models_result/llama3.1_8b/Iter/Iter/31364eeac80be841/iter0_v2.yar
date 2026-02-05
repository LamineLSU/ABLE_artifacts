rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? B8 ?? ?? ?? FF D0 }
        $pattern1 = { FF ?? ?? 50 FF D0 FF ?? ?? ?? ?? }
        $pattern2 = { 8B ?? ?? ?? FF D0 FF ?? ?? ?? ?? E8 }

    condition:
        any of them
}