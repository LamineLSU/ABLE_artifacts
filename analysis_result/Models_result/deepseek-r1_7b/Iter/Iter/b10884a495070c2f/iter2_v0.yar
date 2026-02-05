rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule targeting specific instruction sequences"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF 15 D8 F8 28 ?? ?? ?? ?? }
        $pattern1 = { E8 F3 A5 ?? ?? ?? ?? 8B 45 08 ??: ... }
        $pattern2 = { FF 15 B8 F7 C0 ?? ?? ?? ?? }

    condition:
        any of them
}