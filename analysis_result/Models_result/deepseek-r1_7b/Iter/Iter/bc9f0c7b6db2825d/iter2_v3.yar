rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule targeting memory operations"
        cape_options = "bp0=$pattern0+0,action0=skip,count0=1;bp1=$pattern1+0,action1=skip,count1=1;bp2=$pattern2+0,action2=skip,count2=1"
    
    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? E8 ?? ?? }
        $pattern1 = { 74 1A ?? ?? 8B 45 ?? ?? ?? ?? FF ???? }
        $pattern2 = { 0F 84 8A ?? ?? ?? ?? 8B CE E8 ?? ?? }

    condition:
        any of them
}