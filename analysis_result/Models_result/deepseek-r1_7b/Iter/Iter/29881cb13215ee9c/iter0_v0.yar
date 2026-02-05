rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule targeting memory accesses and stack operations"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8C8 5A ?? 8B45 ?? 0F 84 ?? ?? ??
                      FF7508 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 
                      0F84 ?? ?? ?? ?? 0F 84 ?? }
        $pattern1 = { 6A ?? 5A 8B CE E8C8 ???? 0F 84 ?? ?? 
                      FF7508 ?? ?? ?? ?? 8B45 ?? 0F 84}
        $pattern2 = { 72 03 0F 84 ?? ?? ?? ?? 8B ?? 
                      6A ?? 5A ?? CE E8C8 ???? 85 C0 }

    condition:
        any of them
}