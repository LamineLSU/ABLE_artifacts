rule Bypass_Sample
{
    meta:
        description = "Evasion bypass: JZ jumps before function calls"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 73 5A 4D ?? 5E ?? 89 5F 12 }
        $pattern1 = { 73 5A ?? 4D ?? 6A ?? 36 8B }
        $pattern2 = { 73 5A ?? 4D ?? 6A ?? 36 8B }

    condition:
        any of them
}