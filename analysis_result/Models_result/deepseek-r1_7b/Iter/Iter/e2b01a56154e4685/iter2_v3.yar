rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule targeting specific call and jump sequences"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ??.7412.5A ?? }
        $pattern1 = { E8C8 ?? ?? 740F 5A ?? ??.741B.?? ?? ?? }
        $pattern2 = { 6A5B 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }
}