rule Bypass_Sample
{
    meta:
        description = "Evasion bypass for memory and conditional jump checks"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 4A 8B 5E 6C 7D ?? ?? ?? ?? ?? ?? 9F 87 D3 B5 B5 ?? ?? ?? ?? }
        $pattern1 = { 5C 4A 42 40 40 5C 4A 42 40 40 5C 6E 5B ?? ?? ?? ?? 5C 4A 42 40 40 5C 4A 42 40 40 }
        $pattern2 = { 53 48 6D 71 7F ?? ?? ?? ?? 4A 8B 5E 6C 7D ?? ?? ?? ?? ?? ?? }
}

condition:
    any of them