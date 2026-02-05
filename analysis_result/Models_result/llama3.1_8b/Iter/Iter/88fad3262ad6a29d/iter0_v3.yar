rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? }
        $pattern1 = { E8 FD AF FF FF CA 00 40 3B 84 }
        $pattern2 = { FF 15 0C F2 47 00 CA DD 00 47 F2 0C }

    condition:
        any of them
}