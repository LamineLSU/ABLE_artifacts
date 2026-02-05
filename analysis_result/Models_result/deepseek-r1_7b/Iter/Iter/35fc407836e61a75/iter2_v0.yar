rule Bypass_Sample
{
    meta:
        description = "Evasion bypass detection using specific instruction sequences"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 2D E8 ?? }
        $pattern1 = { 6A 5B 8B CE E8 ?? }
        $pattern2 = { 0F 84 FE FF F0 8C }

    condition:
        any of them
}