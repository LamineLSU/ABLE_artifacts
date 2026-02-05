rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule targeting specific instructions"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? 8B 45 ?? }
        $pattern1 = { 74 ?? 0F 84 8A ?? ??.??.?? }
        $pattern2 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? }

    condition:
        any of them
}