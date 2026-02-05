rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule - Chain of multiple bypass attempts"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 E8 25 05 00 00 ?? ?? ?? ?? ?? }
        $pattern1 = { FF 15 3C E1 DD E2 65 B0 41 00 ?? ?? ?? ?? E8 4B 17 00 00 ?? ?? }
        $pattern2 = { 8B EC F8 75 08 E7 F0 51 00 ?? ?? ?? ?? FF 15 AC B0 41 00 }

    condition:
        any of them
}