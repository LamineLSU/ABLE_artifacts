rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 4D C4 3B 4D FC 73 ?? }
        $pattern1 = { 51 FF 15 ?? ?? ?? ?? }
        $pattern2 = { 01 4D FC 3B 4D FC 73 ?? }

    condition:
        any of them
}