rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { C7 45 FC ?? ?? ?? ?? }
        $pattern1 = { 74 05 E8 ?? ?? FF FF }
        $pattern2 = { 8B 45 E0 C7 45 FC ?? }

    condition:
        any of them
}