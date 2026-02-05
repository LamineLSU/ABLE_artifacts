rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { C3 5E ?? ?? ?? ?? }
        $pattern1 = { 8B 16 50 ?? ?? ?? ?? }
        $pattern2 = { 3D 92 F6 80 ?? ?? ?? ?? }

    condition:
        any of them
}