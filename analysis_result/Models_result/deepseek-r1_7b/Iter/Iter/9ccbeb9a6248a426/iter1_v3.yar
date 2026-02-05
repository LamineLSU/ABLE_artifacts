rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule targeting multiple CALL instructions"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B45E8 ?? ?? ?? ?? }
        $pattern1 = { E84B5C ?? ?? ?? ?? }
        $pattern2 = { 8BE56A ?? ?? ?? ?? }

    condition:
        any of them
}