rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 3D 97 00 00 00 75 DD }
        $pattern1 = { 85 C0 74 06 FF 15 ?? ?? ?? ?? }
        $pattern2 = { 6A 00 FF 15 ?? ?? ?? ?? }

    condition:
        any of them
}