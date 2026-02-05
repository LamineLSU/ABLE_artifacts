rule Bypass_Sample
{
    meta:
        description: "Evasion bypass rule targeting specific call sequences"
        cape_options: "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,count=0"

    strings:
        $pattern0 = { FF7508 E8 C8 FFFF FF ?? }
        $pattern1 = { EC 8B 7F 3D ?? ??
        $pattern2 = { 6A ??5A 8B CE E8 ??
}