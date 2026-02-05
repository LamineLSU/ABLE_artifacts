rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule targeting specific instruction sequences"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A 5A 8B CE E8 ?? ?? ?? ?? F0 4F }
        $pattern1 = { 74 ?F 0F 85 83 C4 ?? 01 8C F3 }
        $pattern2 = { FF FF FF FF FF FF FF FF 6A 5A 8B CE E8 ?? ?? ?? ?? }

    condition:
        any of them
}