rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule targeting specific instructions"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? }
        $pattern1 = { 74 9A ?? ?? ?? ?? 8D 3F ?? ?}
        $pattern2 = { ?? 8B 00 00 00 00 }

    condition:
        any of them
}