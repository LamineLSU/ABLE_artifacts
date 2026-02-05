rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule targeting exit call"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 74 C8 ?? ?? ?? }
        $pattern1 = { E8 C8 FFFF ?? ?? ?? }
        $pattern2 = { FF 5A 00 ?? ?? ?? }
    condition:
        any_of them
}